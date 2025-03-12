# Используем официальный образ Python
FROM python:3.11

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файлы проекта в контейнер
COPY . /app

# Устанавливаем зависимости из requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Открываем порт для API
EXPOSE 8081

# Запускаем сервис
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8081"]
