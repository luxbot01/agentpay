#!/bin/bash
# Render build script

# Install ALL dependencies (including devDependencies for build tools)
npm ci --include=dev

# Generate Prisma client
npx prisma generate

# Build TypeScript
npm run build
