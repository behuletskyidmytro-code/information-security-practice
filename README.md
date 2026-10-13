
# Захищений REST API «Електронний деканат»

Практична робота №1 з дисципліни «Безпека інформаційних систем».

## Технології
- Python 3.12
- FastAPI
- Docker Compose
- SQLite
- Alembic
- JWT
- RBAC

## Запуск
```bash
docker compose up -d --build
```

## Перевірка
- Swagger UI: http://localhost:8000/docs
- Health check: http://localhost:8000/health

## Етапи виконання
1. Підготовка Docker-середовища.
2. База даних і RBAC.
3. Хешування паролів та валідація.
4. JWT-авторизація.
5. Захист вебрівня.

## Поточний стан
Етап 1: API успішно запущено через Docker.
GET /health повертає HTTP 200.
