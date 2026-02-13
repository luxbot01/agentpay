#!/bin/bash
# Render build script

# Install dependencies
npm ci

# Generate Prisma client
npx prisma generate

# Build TypeScript
npm run build
