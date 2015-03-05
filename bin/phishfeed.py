import requests
import urllib

#ENVIRONMENTAL INFORMATION
__author__ = "george@georgestarcher.com (George Starcher)"

"""openphish Class file
    See openphish.com. This class takes a feed type, username and password. It pulls the current feed contents and populates a list of the entries for output.
    Output options are all, asn, or brand matches.
"""

class phishSite:

    def __init__(self,phishJson):

        self.discoverTime = phishJson['discover_time']

        # phishing_kit and emails only exist for complete feeds, not present in extended feeds

        if 'phishing_kit' in phishJson:
            if phishJson['phishing_kit'] is None:
                            self.phishingKit = "None"
            else:
                self.phishingKit = phishJson['phishing_kit']
        else:
            self.phishingKit = "" 

        if 'emails' in phishJson:
            if phishJson['emails'] is None:
                self.emails = "None"
            else:
                self.emails = phishJson['emails']
        else:
            self.emails = "" 

        if phishJson['asn'] is None:
            self.asn =""
        else:
            self.asn = phishJson['asn']

        # asn_name and brand names sometimes contain unicode characters. we remove those characters 

        if phishJson['asn_name'] is None:
            self.asnName = ""
        else:
            self.asnName = phishJson['asn_name'].encode('ascii','ignore')

        if phishJson['brand'] is None:
            self.brand = ""
        else:
             self.brand = phishJson['brand'].encode('ascii','ignore')

        if phishJson['ip'] is None:
            self.brand = ""
        else:
            self.ip = phishJson['ip']

        if phishJson['country_code'] is None:
            self.countryCode = ""
        else:
            self.countryCode = phishJson['country_code']

        if phishJson['url'] is None:
            self.url = ""
        else:
            self.url = phishJson['url']

        if phishJson['tld'] is None:
            self.tld = ""
        else:
             self.tld = phishJson['tld']

    def __str__(self):
        # we output as timestamp and keyvalue pairs to make for automatic parsing in Splunk

        outputString = self.discoverTime+" brand=\""+self.brand+"\" asn="+self.asn+" asn_name=\""+self.asnName+"\" ip="+self.ip+" countryCode="+self.countryCode+" tld="+self.tld+" url=\""+self.url+"\""

        # we append phishing_kit and emails fields if present. these come only from the complete feed.

        if self.phishingKit:
            outputString += " phishing_kit=\""+self.phishingKit+"\""

        if self.emails:
            outputSring += " emails=\""+self.emails+"\""

        return outputString

class eventFeed:

    def __init__(self, feedType, username, password, mimedefang):   

        import json

        if feedType.lower() == 'complete':
            _FEED_URL = "https://openphish.com/prvt-intell/"
        else:
            _FEED_URL = "https://openphish.com/prvt-ex/"

        self.entryList = []
        self.filterList = []
        self.feedText = self.getSitePage(_FEED_URL, username, password)

        entries = self.feedText.split('\n')

        for entry in entries:
            if len(entry) > 0:
                entryDictionary = json.loads(entry)
                if mimedefang=="1":
                    entryDictionary["url"] = entryDictionary["url"].replace('http','hxxp')
                self.entryList.append(phishSite(entryDictionary))
        self.checkpointTime = self.latestTime()

    def __str__(self):

        for entry in self.entryList:
            print entry
        return("")

    def getSitePage(self, feedURL,username, password):
        """ fetch the web page contents for the site """
        try:
            page = requests.get(feedURL, auth=(username, password))
            page.raise_for_status()
            return(page.text)
        except Exception, e:
            raise Exception, "%s" % str(e)

    def filterASN(self, asn, checkpointTime=""):

        if len(self.filterList) > 0:
            workingList = self.filterList
        else:
            workingList = self.entryList

        for entry in workingList:
            if asn in entry.asn:
                if entry.discoverTime > checkpointTime:
                    self.filterList.append(entry)    

    def filterBrand(self, brand, checkpointTime=""):

        if len(self.filterList) > 0:
            workingList = self.filterList
            self.filterList = []
        else:
            workingList = self.entryList

        for entry in workingList:
            if brand.lower() in entry.brand.lower():
                if entry.discoverTime > checkpointTime:
                    self.filterList.append(entry)

    def outputFilter(self):
        output = []
        seen = set()
        for entry in self.filterList:
            if entry not in seen:
                output.append(entry)
                seen.add(entry)
        for entry in output:
            print entry

    def outputAll(self, checkpointTime=""):
        for entry in self.entryList:
            if entry.discoverTime > checkpointTime:
                print entry 

    def latestTime(self):
        timestamp = ""
        for entry in self.entryList:
            if entry.discoverTime > timestamp:
                timestamp = entry.discoverTime
        return(timestamp)
 
def main():

    import sys, argparse 

    parser = argparse.ArgumentParser(description='Obtain feed content from openphish.com')
    parser.add_argument('feedtype', help="complete or extended feed type", choices=['complete', 'extended'], default='extended', action="store")
    parser.add_argument('username', help="feed login username", action="store")
    parser.add_argument('password', help="feed login password", action="store")
    parser.add_argument('mimedefang', help="change http to hxxp in url", choices=['0','1'], action="store")
    parser.add_argument('--asn', help="filter on ASN", dest="asn", action="store")
    parser.add_argument('--brand', help="filter on Brand", dest="brand", action="store")    
    args = parser.parse_args()

    feedtype = args.feedtype
    username = args.username
    password = args.password
    filterASN = args.asn
    filterBrand = args.brand
    mimedefang = args.mimedefang
    
    try:
        feed = eventFeed(feedtype, username, password, mimedefang)
        if filterASN:
            feed.filterASN(filterASN)
        if filterBrand:
            feed.filterBrand(filterBrand)

        if filterASN or filterBrand:
            feed.outputFilter()
        else:
            feed.outputAll()  

    except Exception, e:
        raise Exception, "%s" % str(e)

if __name__ == "__main__":

    main()

