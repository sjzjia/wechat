# 使用官方 Python 镜像作为基础镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 复制当前目录下的所有文件到容器的工作目录
COPY . /app

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --upgrade openai

# 暴露容器的端口
EXPOSE 80

# 启动应用
CMD ["python", "app.py"]
