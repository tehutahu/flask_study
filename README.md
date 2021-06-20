# flask_study

## Get Start
### Install
`pip install -r requirements.txt`

### Run
- CMD  
`set FLASK_APP="run.py"`

- PowerShell  
`$env:FLASK_APP="run.py"`

- bash  
`export FLASK_APP="run.py"`

```
(env)$ cd [anywhere_sample] 
(env)$ flask db init
(env)$ flask db migrate -m 'first migrate'
(env)$ flask db upgrade
(env)$ flask run
```