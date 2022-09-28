FROM node:16 as builder
# multi-stage build stage 1

# create directory
WORKDIR /build/src/app

# copy packages source
COPY ./package.json ./yarn.lock /build/src/app/

# Install all packages
RUN yarn
COPY . .

RUN npx prisma generate
RUN npx prisma migrate dev
RUN npx prisma db seed

RUN yarn build

FROM node:16 as runner

# set new work directory
WORKDIR /src/app

# copy the files from build stage 1
COPY --from=builder /build/src/app /src/app

EXPOSE 3000
# run the app
CMD ["yarn",  "start:prod"]