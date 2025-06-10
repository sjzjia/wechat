使用 Caddy反向代理 Gemini启动：
docker run -d \
    --name=caddy \
    -p 80:2019 \
    -p 443:443 \
    -v /data/caddy/Caddyfile:/etc/caddy/Caddyfile \
    -v /data/caddy/caddy_data:/data \
    -v /data/caddy/caddy_config:/config \
    --link=gemini \
    caddy



1、只需要文字回复Gemini启动：docker run -itd -e WECHAT_TOKEN="WECHAT_TOKEN" -e GEMINI_API_KEY="GEMINI_API_KEY"  --name gemini gemini  

2、需要图片支持，使用app.py-images，>2000字节后会自动转成图片回复，<2000字节后仍然使用文字回复，启动需要4个变量，可在微信公众号后台查询，图片格式需要中文字体，代码中的字体用的是SourceHanSansSC-Regular.otf，可访问谷歌字体库下载：https://github.com/adobe-fonts/source-han-sans  

**注意：由于个人公众号不能使用客服消息接口，所以使用redis存储结果，需要redis 容器**  

容器启动示例docker run -itd -e WECHAT_TOKEN="WECHAT_TOKEN" -e GEMINI_API_KEY="GEMINI_API_KEY"  -e WECHAT_APPID="WECHAT_APPID" -e WECHAT_APPSECRET="WECHAT_APPSECRET" -e REDIS_HOST="redis" -e REDIS_PORT="6379" --link=redis --name gemini gemini  

下面是个使用图片询问2025年高考数学题目的实例，如果发送过去是图片或者回复的数字超过 2000 字节的都需要这种方式获取结果，因为公众号限制不能大于2048字节

<img width="805" alt="image" src="https://github.com/user-attachments/assets/b77857a6-f0a3-457e-8900-bd5141e045a9" />


