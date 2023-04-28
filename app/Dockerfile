FROM gplane/pnpm as Builder

RUN mkdir -p /home/openeuler-certificate/web
WORKDIR /home/openeuler-certificate/web
COPY . /home/openeuler-certificate/web

RUN pnpm install

RUN pnpm build

# FROM nginx:1.20.0

# COPY ./deploy/test-login.html /usr/share/nginx/html/test-login.html
FROM swr.cn-north-4.myhuaweicloud.com/opensourceway/openeuler/nginx:1.22.0-22.03-lts
COPY --from=Builder /home/openeuler-certificate/web/dist/ /usr/share/nginx/html/
RUN chmod -R 755 /usr/share/nginx/html
COPY ./deploy/nginx/nginx.conf /etc/nginx/nginx.conf


ENV RUN_USER nginx
ENV RUN_GROUP nginx
EXPOSE 8080
ENTRYPOINT ["nginx", "-g", "daemon off;"]

