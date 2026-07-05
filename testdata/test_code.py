def process_user_input(user_data):
    """这段代码故意写了几个安全问题，用来测试 verdict"""

    # 问题1: SQL 注入
    username = user_data.get("username")
    query = f"SELECT * FROM users WHERE name = '{username}'"
    db.execute(query)

    # 问题2: 硬编码密钥
    api_key = "sk-abc123def456ghi789jkl012mno345"
    password = "super_secret_password_123"

    # 问题3: eval 滥用
    result = eval(user_data["expression"])

    # 问题4: innerHTML XSS
    element.innerHTML = user_data["comment"]

    # 问题5: MD5 哈希密码
    hashed = hashlib.md5(password.encode()).hexdigest()

    # 问题6: 打印敏感信息
    print(f"User password: {password}")

    return result
