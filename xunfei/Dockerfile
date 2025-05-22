# 使用 Python 官方镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /xf

# 复制依赖文件并安装
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 复制应用代码
COPY app.py .

# 暴露端口
EXPOSE 80

# 启动应用
CMD ["python", "app.py"]
