import os

base = "alert tcp any any -> any any (msg:\"%s rule\"; content:\"GET %s HTTP\"; content:\"Host: %s\"; sid:%d; rev:1;)"
ip_base = "alert tcp any any -> [%s] any (msg:\"%s rule\"; sid:%d; rev:1;)"

idx = 1
with open("mal-sites.txt","r") as f:
    datas = f.readlines()
    for data in datas:
        data = data.rstrip()
        if "https" in data:
            _url = data.split("https://")[1]
            _url = _url.split("/")
            if '' in _url:
                _url.remove('')
            
            if len(_url) > 1:
                print "# impossible " + data
                continue
            else:
                addrs = []
                _out = os.popen("nslookup " + _url[0]).read().split('\n')
                for i in _out:
		    if "Address: " in i:
			addrs.append(i.split("Address: ")[1])        
                print ip_base % (",".join(i for i in addrs), _url[0], 10000+idx)
        else:
            _url = data.split("http://")[1]
            lev = _url.split(".")
            for levName in lev:
                if levName != "www":
                    ruleName = levName
                    break
                    
            print base % (levName, "/"+"/".join(a for a in _url.split("/")[1:]), _url.split("/")[0], 10000 + idx)
        idx += 1

