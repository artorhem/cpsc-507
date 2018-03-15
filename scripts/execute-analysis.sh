while read p || [[ -n $p ]]; do
  python /cli.py --url $p --replace --push
done </home/repos.txt