FROM --platform=linux/amd64 nginx
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/conf.d/file-assets.conf /etc/nginx/conf.d/file-assets.conf
