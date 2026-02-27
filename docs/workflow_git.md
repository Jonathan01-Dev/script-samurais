# Workflow Git (cas: seul le chef est sur le repo ecole)

## Chef (repo officiel)
- Possede le repo principal
- Relit/merge les PR
- Tag les sprints

## Membres 2/3/4 (sans acces direct)
- Fork du repo officiel vers leur compte perso
- Branche feature sur leur fork
- Pull Request vers le repo du chef (`develop`)

## Sequence membre (fork)
1. Fork sur GitHub
2. Clone du fork:
   - `git clone git@github.com:<membre>/script-samurais.git`
3. Ajouter upstream (repo chef):
   - `git remote add upstream git@github.com:<chef>/script-samurais.git`
4. Sync develop:
   - `git fetch upstream`
   - `git switch develop || git switch -c develop`
   - `git reset --hard upstream/develop`
   - `git push origin develop --force-with-lease`
5. Branche de travail:
   - `git switch -c feature/sX-membre-tache`
6. Commit + push:
   - `git add . && git commit -m "feat(...): ..."`
   - `git push -u origin feature/sX-membre-tache`
7. Ouvrir PR: fork -> repo chef, base `develop`

## Sequence chef
1. `git switch develop && git pull origin develop`
2. Review PR
3. Merge PR vers `develop`
4. Fin de sprint:
   - `git tag sprint-X`
   - `git push origin sprint-X`
