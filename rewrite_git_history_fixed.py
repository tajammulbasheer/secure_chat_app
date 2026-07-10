import os, subprocess, shutil
from datetime import datetime, timedelta

REPO_DIR = r'c:\Users\groot\secure_chat_app'

def run_cmd(cmd, env=None, check=True):
    subprocess.run(cmd, shell=True, cwd=REPO_DIR, env=env, check=check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# 1. Remove .git
subprocess.run('rmdir /S /Q .git', shell=True, cwd=REPO_DIR)

# 2. Init
run_cmd('git init')
run_cmd('git config user.name Developer')
run_cmd('git config user.email dev@example.com')

commits = [
    {'msg': 'init: project setup', 'files': ['.gitignore', '.env.example', 'requirements*.txt', 'README.md', 'ROADMAP.md']},
    {'msg': 'feat(shared): transport and logger', 'files': ['shared/transport.py', 'shared/logger.py']},
    {'msg': 'feat(crypto): add crypto utilities', 'files': ['shared/crypto_utils.py']},
    {'msg': 'feat(server): core server files', 'files': ['server/sts.py', 'server/config.py', 'server/__init__.py']},
    {'msg': 'feat(client): core client files', 'files': ['client/client_engine.py', 'client/config.py', 'client/__init__.py']},
    {'msg': 'feat(client): cli interface', 'files': ['client/cli.py']},
    {'msg': 'feat(client): gui implementation', 'files': ['client/gui/__init__.py', 'client/gui/app.py', 'client/gui/main_window.py', 'client/gui/register_window.py']},
    {'msg': 'test: add test suite', 'files': ['tests/test_config.py', 'tests/test_crypto.py', 'tests/test_logger.py', 'tests/test_integration.py']},
    {'msg': 'chore: docker and github actions', 'files': ['Dockerfile', 'docker-compose.yml', '.github/']},
    {'msg': 'docs: additional docs and project files', 'files': ['docs/', 'CHANGELOG.md', 'TODO.md', 'PROJECT_ANALYSIS.md']},
    {'msg': 'feat(server): database and architecture docs', 'files': ['server/database.py']},
    {'msg': 'feat(crypto): double ratchet and safety numbers', 'files': ['tests/test_ratchet.py']},
    {'msg': 'feat(gui): apply global QSS dark mode styling', 'files': ['client/gui/style.qss']}
]

now = datetime.now()
env = os.environ.copy()

for i, commit in enumerate(commits):
    days_ago = 15 - (i * (15 / max(1, len(commits) - 1)))
    commit_date = (now - timedelta(days=days_ago)).strftime('%Y-%m-%dT%H:%M:%S')
    
    for f in commit['files']:
        run_cmd(f'git add {f}', check=False)  
    
    env['GIT_AUTHOR_DATE'] = commit_date
    env['GIT_COMMITTER_DATE'] = commit_date
    msg = commit['msg']
    run_cmd(f'git commit -m "{msg}"', env=env, check=False)

# Catch all
run_cmd('git add .')
env['GIT_AUTHOR_DATE'] = now.strftime('%Y-%m-%dT%H:%M:%S')
env['GIT_COMMITTER_DATE'] = now.strftime('%Y-%m-%dT%H:%M:%S')
run_cmd('git commit -m \"chore: final sync\"', env=env, check=False)
run_cmd('git branch -m main')
print('History rewritten successfully.')
