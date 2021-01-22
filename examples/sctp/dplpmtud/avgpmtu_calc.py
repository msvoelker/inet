import numpy as np
import sqlite3
import os

dirname = os.path.dirname(__file__)
dirname += "/" if dirname else ""
path = dirname + "results/"

mtus = np.arange(1280, 1501, 4)
algs = ["Up","Down","OptUp","Binary","Jump"]
for alg in algs:
	print(alg)
	for mtu in mtus:
		#General-alg=Binary,mtu=1280-#0.vec
		file = path + "General-alg="+alg+",mtu="+str(mtu)+"-#0.vec"
		#print(file)
		conn = sqlite3.connect(file)
		c = conn.cursor()

		lastPmtu = 0
		durations = 0
		avgPmtu = 0

		for row in c.execute("""
	select simtimeRaw, value 
	from vectorData 
	where vectorId = (
		select vectorId 
		from vector 
		where moduleName = 'Simple.sender.sctp' and vectorName = 'DPLPMTUD: PMTU 1:10.0.0.10'
	)
	order by simtimeRaw
	"""):
			time = row[0]/1000000000 # in ms
			pmtu = row[1]
			if lastPmtu != 0:
				duration = time - lastTime
				#print("had " + str(lastPmtu) + " for " + str(duration))
				avgPmtu += lastPmtu * duration
				durations += duration
			else:
				time += 20 # search algorithm starts 20ms later than the first value were recorded
				
			lastTime = time
			lastPmtu = pmtu

		if (durations > 0):
			avgPmtu /= durations
		else:
			avgPmtu = lastPmtu
		print(str(mtu) + " " + str(avgPmtu))

