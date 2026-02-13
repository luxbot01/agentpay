#!/bin/bash
# Render start script

# Push schema to database (creates tables if needed)
npx prisma db push

# Start the application
npm start
