#!/bin/bash
# InboxScore.ai - One-shot GitHub + Deployment Setup
# Run this from your Mac Terminal

echo "🚀 Setting up InboxScore.ai on GitHub..."
echo ""

# Step 1: Clean up broken .git from sandbox
cd ~/InboxScore.ai/inboxscore
echo "Step 1: Cleaning up old .git directory..."
rm -rf .git
echo "✅ Done"

# Step 2: Initialize fresh git repo
echo ""
echo "Step 2: Initializing fresh git repo..."
git init
git add -A
git commit -m "Initial commit - InboxScore.ai email deliverability diagnostic tool"
echo "✅ Done"

# Step 3: Create GitHub repo and push
echo ""
echo "Step 3: Creating GitHub repo and pushing..."
echo "This will use the GitHub CLI (gh) to create the repo."
echo ""

# Check if gh is installed
if command -v gh &> /dev/null; then
    gh repo create inboxscore-ai --public --source=. --remote=origin --push
    echo "✅ Pushed to GitHub!"
else
    echo "⚠️  GitHub CLI (gh) not installed."
    echo ""
    echo "Option A: Install it with: brew install gh"
    echo "Option B: Create the repo manually on github.com, then run:"
    echo ""
    echo "  git remote add origin https://github.com/YOUR_USERNAME/inboxscore-ai.git"
    echo "  git branch -M main"
    echo "  git push -u origin main"
fi

echo ""
echo "🎉 Done! Next step: Connect to Railway for deployment."
echo "   1. Go to https://railway.app"
echo "   2. Click 'New Project' → 'Deploy from GitHub Repo'"
echo "   3. Select 'inboxscore-ai'"
echo "   4. Railway will auto-detect the Procfile and deploy!"
echo "   5. Add your custom domain: inboxscore.ai"
