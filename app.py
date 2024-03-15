from flask import Flask, jsonify, request
from flask_cors import CORS, cross_origin
import json
from getting.response import message_status
from getting.gamecreator.auth import login_pw, login_token
from getting.auth import token, verify_token
from datetime import datetime
import pymysql
from env import db_config
from pymysql import Error
from getting.pymysql.sql import query, insert, update

app = Flask(__name__)
# cors = CORS(app)


@app.route("/apis/gamecreator/auth/login", methods=["POST"])
def login():
    "生成或返回 auth_token"
    """
    auth_token 是一串全新随机的字符串，目的是用于验证使用相关服务时候的所有权。
    这样就不需要频繁的去请求GameCreator官方登陆系统来验证账号。
    """

    # 获取JSON数据
    data = request.get_json()
    request_type = int(data.get("type", 0))
    username = data.get("username", None)
    password = data.get("password", None)
    user_token = data.get("token", None)

    if request_type != 0 | request_type != 1:
        return jsonify(message_status(None, "请求类型错误"))

    user_data = None
    if request_type == 1 and username is not None and password is not None:
        # 使用账号密码登录GC平台
        user_data = login_pw(username, password)

    if request_type == 0 and user_token is not None:
        # 使用token登录GC平台
        user_data = login_token(user_token)

    if user_data is None:
        # 如果数据空
        return jsonify(message_status(None, "登录信息错误-1"))

    request_code = user_data.get("code", None)
    if request_code is None:
        # 如果请求状态为空
        return jsonify(message_status(None, "登录信息错误-2"))

    if request_code != 20000:
        # 如果请求失败
        return jsonify(message_status(None, "请求失败"))

    request_data = user_data.get("data", None)
    if request_data is None:
        # 如果请求数据为空
        return jsonify(message_status(None, "请求数据为空"))

    uid = request_data.get("id")
    user_name = request_data.get("nickname")
    payload = {
        "uid": uid,
        "username": user_name,
    }

    # 连接到数据库
    connection = pymysql.connect(**db_config())
    # 创建游标
    cursor = connection.cursor()

    try:
        # 密钥
        query_sql = """
        SELECT *
        FROM auth_secret_key
        WHERE type = 'gamecreator_auth';
        """
        execute, auth_key = query(cursor, query_sql)
        if execute < 1:
            return jsonify(message_status(None, "key不存在, 请联系开发者"))
        auth_key = auth_key[0]

        # 尝试获取现有记录
        query_sql = """
        SELECT *
        FROM gamecreator_auth
        WHERE uid =  %(uid)s;
        """
        execute, auth_data = query(cursor, query_sql, ({"uid": uid}))

        if execute < 1:
            # 如果记录不存在，创建一个新记录
            insert_sql = """
            INSERT INTO gamecreator_auth (uid, username, auth_token, updated_at)
            VALUES (%(uid)s, %(username)s, %(auth_token)s, %(updated_at)s);
            """
            execute, auth_data = insert(
                insert_sql,
                (
                    {
                        "uid": uid,
                        "username": user_name,
                        "auth_token": token(auth_key.get("secret_key"), payload),
                        "updated_at": datetime.now(),
                    }
                ),
            )
            # 提交更改
            connection.commit()
            auth_data = auth_data[0]

        else:
            auth_data = auth_data[0]
            # GC平台用户名是否变更
            if user_name != auth_data.get("username"):
                update_sql = """
                UPDATE gamecreator_auth
                SET username = %(username)s, updated_at = %(updated_at)s
                WHERE uid =  %(uid)s;
                """
                update(
                    cursor,
                    update_sql,
                    (
                        {
                            "username": user_name,
                            "updated_at": datetime.now(),
                        }
                    ),
                )

            # 验证 auth_token 是否过期失效
            if not verify_token(
                auth_key.get("secret_key"), auth_data.get("auth_token")
            ):
                update_sql = """
                UPDATE gamecreator_auth
                SET auth_token = %(auth_token)s, updated_at = %(updated_at)s
                WHERE uid =  %(uid)s;
                """
                update(
                    cursor,
                    update_sql,
                    (
                        {
                            "auth_token": token(auth_key.get("secret_key"), payload),
                            "updated_at": datetime.now(),
                            "uid": uid,
                        }
                    ),
                )

            # 提交更改
            connection.commit()

        return jsonify(message_status(auth_data, "登录成功"))

    except Error as e:
        print("Error:", e)


@app.route("/apis/gamecreator/auth/status", methods=["POST"])
def status():
    "查询登录状态"
    data = json.loads(request.body.decode("utf-8"))
    auth_token = data.get("auth_token")

    if auth_token is None:
        return jsonify(message_status(None, "提交信息为空"))

    # 连接到数据库
    connection = pymysql.connect(**db_config())
    # 创建游标
    cursor = connection.cursor()

    # 密钥
    query_sql = """
    SELECT *
    FROM auth_secret_key
    WHERE type = 'gamecreator_auth';
    """
    execute, auth_key = query(cursor, query_sql)
    if execute < 1:
        return jsonify(message_status(None, "key不存在, 请联系开发者"))
    auth_key = auth_key[0]

    # 验证auth_token是否过期失效
    if not verify_token(auth_key.get("secret_key"), auth_token):
        # 尝试获取现有记录
        query_sql = """
        SELECT *
        FROM gamecreator_auth
        WHERE auth_token =  %(auth_token)s;
        """
        execute, auth_data = query(cursor, query_sql, ({"auth_token": auth_token}))
        if execute < 1:
            return jsonify(message_status(None, "auth_token 不存在, 请尝试重新登录"))
        return jsonify(message_status(auth_data[0], "登录成功"))
    else:
        return jsonify(message_status(None, "登录信息错误, 或 auth_token 过期"))


if __name__ == "__main__":
    app.run(debug=True, port=9002)
