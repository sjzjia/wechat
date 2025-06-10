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



Gemini启动：docker run -itd -e WECHAT_TOKEN="WECHAT_TOKEN" -e GEMINI_API_KEY="GEMINI_API_KEY"  --name gemini gemini
需要回复成图片格式的可以使用 app.py-images，>2000字节后会自动转成图片回复，<2000字节后仍然使用文字回复，启动需要4个变量，可在微信公众号后台查询 docker run -itd -e WECHAT_TOKEN="WECHAT_TOKEN" -e GEMINI_API_KEY="GEMINI_API_KEY"  -e WECHAT_APPID="WECHAT_APPID" -e WECHAT_APPSECRET="WECHAT_APPSECRET" --name gemini gemini
图片格式需要中文字体，代码中的字体用的是SourceHanSansSC-Regular.otf，可访问谷歌字体库下载：https://github.com/adobe-fonts/source-han-sans
