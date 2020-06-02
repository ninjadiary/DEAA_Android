import requests, time, os
from os import walk
from bs4 import BeautifulSoup
from subprocess import Popen, PIPE

url = 'https://www.apkmirror.com/wp-content/themes/APKMirror/download.php?id='

binwalk_noresult = """
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------

"""

def executeCmd(commandArgList):
	p = Popen(commandArgList, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
	output, err = p.communicate()	# put b"data to stdin" as input. Give it to communicate()
	rc = p.returncode
	return {"return_code" : rc, "output" : output, "error" : err}

def getFromManifest(txt, mainDir):
	perms = []
	soup = BeautifulSoup(txt)
	netsec_configs = None
	# find permissions
	permissions = soup.findAll("uses-permission")
	for permission in permissions:
		protLevel = None
		if permission.has_attr("android:protectionLevel"):
			protLevel = permission["android:protectionLevel"]
		perms.append({"name":permission["android:name"], "level" : protLevel})
	permissions = soup.findAll("permission")
	for permission in permissions:
		protLevel = None
		if permission.has_attr("android:protectionLevel"):
			protLevel = permission["android:protectionLevel"]
		perms.append({"name":permission["android:name"], "level" : protLevel})
	# find package
	package = soup.find("manifest")["package"]
	# find network security configuration
	appTag = soup.find("application")
	netsecconf = None
	if appTag != None and appTag.has_attr("android:networkSecurityConfig"):
		netsecconf = appTag["android:networkSecurityConfig"]
	if netsecconf != None and netsecconf != list and netsecconf.startswith("@xml/"):
		netsecconf_filename_xml = netsecconf.split("/")[1]
		netsec_xml_path = mainDir+"res/xml/"+netsecconf_filename_xml+".xml"
		if os.path.isfile(netsec_xml_path):
			try:
				netsec_configs = open(netsec_xml_path, "r").read()
			except:
				print "Error Opening Network Security Configuration File"
	
	# return struct
	return {"permissions" : perms, "package" : package, "network_security_configuration" : netsec_configs}

def analyzeRawFiles(rawFolder):
	files_analyzed = []
	if os.path.isdir(rawFolder):
		for (dirpath, dirnames, filenames) in walk(rawFolder):
			for filename in filenames:
				fullPath = dirpath + "/" + filename
				files_analyzed.append({"dir" : fullPath , "data" : analyzeRawFile(fullPath)})
			for dirname in dirnames:
				files_analyzed.extend(analyzeRawFiles(dirname))
	return files_analyzed

def analyzeRaw(rawFolder):
	rawFiles = analyzeRawFiles(rawFolder)
	for rawFile in rawFiles:
		print "Raw >> ", rawFile["dir"], rawFile["data"]

def analyzeRawFile(raw_file):
	fileFormat = str()
	# file <file>
	execStruct = executeCmd("file " + raw_file)
	rc = execStruct["return_code"]
	if rc == 0:
		fileFormat += execStruct["output"]
	fileFormat += "\n"
	# binwalk <file>
	execStruct = executeCmd("binwalk " + raw_file)
	rc = execStruct["return_code"]
	if rc == 0:
		if execStruct["output"] != binwalk_noresult:
			fileFormat += execStruct["output"]
	try:
		if fileFormat.find("Certificate") >= 0:
			execStruct = executeCmd("openssl x509 -in "+raw_file+" -text")
			if execStruct["return_code"] != 0 and fileFormat.find("in DER format"):
				execStruct = executeCmd("openssl x509 -in "+raw_file+" -inform der -text")
				if execStruct["return_code"] == 0:
					fileFormat += execStruct["output"]
			else:
				fileFormat += execStruct["output"]
	except:
		pass
	return fileFormat



apks_download_total = 3000

go_back = apks_download_total / 2
go_forth = apks_download_total / 2
offset = 0

# sleep time seconds
stime = 120

downloadMode = False
global_permission_doc = {}

# download files
for i in range(699840+offset-go_back, 699840-offset+go_forth):
	if downloadMode:
		if os.path.isfile("apks/file_"+str(i)) == False:
			req_url = url + str(i)
			try:
				r = requests.get(req_url, allow_redirects=True)
			except e:
				print "Error for ", req_url, str(e)
			if r.status_code == 200 and os.path.isfile("apks/file_" + str(i)) == False:
				open('apks/file_' + str(i) + '.apk', 'wb').write(r.content)
			print i, r.status_code
			time.sleep(stime)

print "Files Downloaded"

for i in range(699840+offset-go_back, 699840-offset+go_forth):
	if os.path.isfile("apks/file_"+str(i)) == False:
		print "Unpacking...", i
		os.system("apktool -s -f d -o unpacks/base_"+str(i)+" apks/file_"+str(i)+".apk")

# list directories and files
fnames = []
dnames = []
for (dirpath, dirnames, filenames) in walk("unpacks/"):
	fnames.extend(filenames)
	dnames.extend(dirnames)
	break

# get each extracted apk's manifest and list the permissions for each app
for app in dnames:
	mainDir = "unpacks/"+app+"/"
	flookup = "unpacks/"+app+"/"+"AndroidManifest.xml"
	rawFolder = "unpacks/"+app+"/res/raw"
	
	# Analyze manifest
	if os.path.isfile(flookup):
		ftxt = open(flookup, "r").read()
		try:
			manifest_data = getFromManifest(ftxt, mainDir)
		except:
			print "Cannot parse manifest of ", app
			continue
		if manifest_data == None:
			continue
		print manifest_data["package"]
		if len(manifest_data["permissions"]) > 0:
			for perm in manifest_data["permissions"]:
				if global_permission_doc.has_key(perm["name"]) == False:
					global_permission_doc[perm["name"]] = [manifest_data["package"]]
				else:
					global_permission_doc[perm["name"]].append(manifest_data["package"])	
	else:
		print flookup, "File Not Found"
	
	# Analyze raw files
	analyzeRaw(rawFolder)

for permission in global_permission_doc.keys():
	print permission, len(global_permission_doc[permission])


