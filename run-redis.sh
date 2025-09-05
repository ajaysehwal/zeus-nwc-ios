#!/bin/bash

# Redis Runner Script for Zeus NWC Server
echo "🚀 Starting Redis for Zeus NWC Server..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Check if Redis container already exists
if docker ps -a --format "table {{.Names}}" | grep -q "zeus-redis"; then
    echo "🔄 Redis container already exists. Starting it..."
    docker start zeus-redis
else
    echo "🐳 Creating and starting Redis container..."
    docker run -d \
        --name zeus-redis \
        --restart unless-stopped \
        -p 6379:6379 \
        -v redis_data:/data \
        -e REDIS_PASSWORD=admin \
        redis:7.2-alpine \
        redis-server --requirepass admin --appendonly yes
fi

# Wait for Redis to be ready
echo "⏳ Waiting for Redis to be ready..."
sleep 5

# Check Redis status
if docker ps --format "table {{.Names}}" | grep -q "zeus-redis"; then
    echo "✅ Redis is running successfully!"
    echo "📍 Redis URL: localhost:6379"
    echo "🔑 Password: your_redis_password_here"
    echo ""
    echo "📊 Redis Info:"
    docker exec zeus-redis redis-cli -a your_redis_password_here info server | head -5
    echo ""
    echo "🛑 To stop Redis: docker stop zeus-redis"
    echo "🗑️  To remove Redis: docker rm -f zeus-redis"
    echo "📝 To view logs: docker logs -f zeus-redis"
    echo "🔗 To connect: docker exec -it zeus-redis redis-cli -a your_redis_password_here"
else
    echo "❌ Failed to start Redis. Check logs with: docker logs zeus-redis"
    exit 1
fi
