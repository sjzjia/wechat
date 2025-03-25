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
