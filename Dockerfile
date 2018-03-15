FROM python

COPY ./src /
ADD requirements.txt /
ADD scripts/execute-analysis.sh execute-analysis.sh 


RUN pip install -r requirements.txt
RUN chmod +x execute-analysis.sh 

CMD ./execute-analysis.sh
