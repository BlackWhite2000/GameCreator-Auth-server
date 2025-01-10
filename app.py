# 依赖库
from flask import Flask, jsonify, request, Blueprint
from loguru import logger

# 创建数据库连接，封装了 from sqlalchemy import create_engine
"""
def create_session(url):
    engine = create_engine(url, echo=False)
    Session = sessionmaker(bind=engine)
    session = Session()
    return session
"""
from utils.database import create_session

# 数据库地址
from config.database import GAMECREATOR_MYSQL_DATABASE_URL

# 表
from models.gamecreator import GameCreatorAuth

# auth_token key
from config.auth import GAMECREATOR_AUTH_SECRET_KEY 

 # 可在getting库中找到相同代码，此处是将库的函数放到了本地。目的是为了编译后的虚拟环境能更小点，因为那个库用到太多依赖了。
from utils.response import message_status
from utils.auth import token, verify_token
from utils.gamecreator.auth import login_pw, login_token, login_code

gamecreator_auth = Blueprint('gamecreator_auth', __name__)

@gamecreator_auth.route("/apis/gamecreator/auth/login", methods=["POST"])
def login():
    """
    生成或返回 auth_token

    auth_token 是一串全新随机的字符串，目的是用于验证使用相关服务时候的所有权。
    这样就不需要频繁的去请求GameCreator官方登陆系统来验证账号。
    """
    data = request.get_json()
    request_type = int(data.get("type", 0))
    username = data.get("username", None)  # 手机号、邮箱、用户名
    password = data.get("password", None)
    user_token = data.get("token", None)
    phone = data.get("phone", None)
    code = data.get("code", None)

    if request_type != 0 and request_type != 1 and request_type != 2:
        return jsonify(message_status(None, "请求类型错误"))
    
    user_data = None
    if request_type == 1 and username is not None and password is not None:
        # 使用账号密码登录GC平台
        user_data = login_pw(username, password)

    if request_type == 0 and user_token is not None:
        # 使用token登录GC平台
        user_data = login_token(user_token)
    
    if request_type == 2 and phone is not None and code is not None:
        # 使用手机短信登录GC平台 - 需自行获取短信验证码
        user_data = login_code(phone, code)

    if user_data is None:
        return jsonify(message_status(None, "登录信息错误-1"))
    
    request_code = user_data.get("code", None)
    if request_code is None:
        return jsonify(message_status(None, "登录信息错误-2"))

    if request_code != 20000:
        return jsonify(message_status(None, "请求失败"))

    request_data = user_data.get("data", None)
    if request_data is None:
        return jsonify(message_status(None, "请求数据为空"))

    uid = request_data.get("id")
    user_name = request_data.get("nickname")
    payload = {
        "uid": uid,
        "username": user_name,
    }

    session = create_session(GAMECREATOR_MYSQL_DATABASE_URL)
    try:
        # 尝试获取现有记录
        auth = session.query(GameCreatorAuth).filter(GameCreatorAuth.uid == uid).first()

        if auth is None:
            # 如果记录不存在，创建一个新记录
            payload["auth_token"] = token(GAMECREATOR_AUTH_SECRET_KEY, payload)
            auth = GameCreatorAuth(**payload)
            session.add(auth)
        else:
            # GC平台用户名是否变更
            if auth.username != user_name:
                auth.username = user_name
            # auth_token 是否过期
            if not verify_token(GAMECREATOR_AUTH_SECRET_KEY, auth.auth_token):
                auth.auth_token = token(GAMECREATOR_AUTH_SECRET_KEY, payload)
        
        session.commit()
        return jsonify(message_status({
            "uid": auth.uid,
            "username": auth.username,
            "auth_token": auth.auth_token
        }, "登录成功"))

    except Exception as e:
        logger.error(f"数据库错误 => {e}")
        session.rollback()  
        return jsonify(message_status(None, "数据库错误"))
    finally:
        session.close()


@gamecreator_auth.route("/apis/gamecreator/auth/status", methods=["POST"])
def status():
    """
    查询登录状态

    通过查询前端发送的auth_token是否有效
    """
    data = request.get_json()
    auth_token = data.get("auth_token")

    if not auth_token:
        # 直接判断 auth_token 是否为空
        return jsonify(message_status(None, "提交信息为空"))
    
    if not verify_token(GAMECREATOR_AUTH_SECRET_KEY, auth_token):
        # 如果 token 无效，直接返回
        return jsonify(message_status(None, "auth_token无效"))
    
    session = create_session(GAMECREATOR_MYSQL_DATABASE_URL)
    try:
        # 尝试根据 auth_token 查询用户
        auth = session.query(GameCreatorAuth).filter(GameCreatorAuth.auth_token == auth_token).first()

        if auth is None:
            # 如果没有找到相应的记录
            return jsonify(message_status(None, "账号不存在"))
        
        return jsonify(message_status({
            "uid": auth.uid,
            "username": auth.username,
            "auth_token": auth.auth_token
        }, "auth_token有效"))

    except Exception as e:
        logger.error(f"数据库错误 => {e}")
        return jsonify(message_status(None, "数据库错误"))
    finally:
        session.close()

if __name__ == "__main__":
    app = Flask(__name__)
    app.register_blueprint(gamecreator_auth)
    app.run(port=9002, debug=True)