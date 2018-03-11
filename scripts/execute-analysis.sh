while read p || [[ -n $p ]]; do
  python /cli.py --url $p --replace
done </home/repos.txt