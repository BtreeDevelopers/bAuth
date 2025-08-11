# Use uma imagem base do Node.js
FROM node:18-alpine

# Defina o diretório de trabalho no contêiner
WORKDIR /app

# Copie os arquivos de dependências
COPY package*.json ./

# Instale as dependências de produção
RUN npm install

# Copie o restante dos arquivos da aplicação
COPY . .

# Compile o código TypeScript
RUN npm run build

# Exponha a porta em que a aplicação será executada
EXPOSE 3000

# Comando para iniciar a aplicação
CMD [ "node", "dist/index.js" ]