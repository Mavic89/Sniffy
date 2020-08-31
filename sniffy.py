
from PySide2 import QtCore, QtWidgets, QtGui
from sys import exit
from scapy.all import *
import time

class GUI(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.startbutton=QtWidgets.QPushButton("Start")
        self.headerlabel =QtWidgets.QLabel(self)
        self.headerlabel.setText("Sniff")
        self.headerlabel.move(300,5)
        self.headerlabel.resize(400,100)
        self.headerlabel.setStyleSheet('color:white;font-weight:bold;font-size:80px;')
        self.pic=QtWidgets.QLabel(self)
        self.pixmap=QtGui.QPixmap("nose.png")
        self.pic.setPixmap(self.pixmap)
        self.pic.move(750,20)
        self.pic.resize(50,50)
        self.durationLabel=QtWidgets.QLabel(self)
        self.durationLabel.setText("Duration(seconds):")
        self.durationLabel.move(10,225)
        self.durationLabel.setStyleSheet('color:white;')
        self.DTextBox = QtWidgets.QLineEdit(self)
        self.DTextBox.move(10,250)
        self.DTextBox.resize(50,20)
        self.filterByLabel =QtWidgets.QLabel(self)
        self.filterByLabel.setText("Filter By:")
        self.filterByLabel.move(15,120)
        self.filterByLabel.setStyleSheet('color:white;font-weight:bold;font-size:15px;text-decoration:underline;')
        self.toruLabel=QtWidgets.QLabel(self)
        self.toruLabel.setText("TYPE:")
        self.toruLabel.move(10,185)
        self.toruLabel.setStyleSheet('color:white;')
        self.hostlabel =QtWidgets.QLabel(self)
        self.hostlabel.setText("Host:")
        self.hostlabel.move(10,145)
        self.hostlabel.setStyleSheet('color:white;')
        self.Htextbox=QtWidgets.QLineEdit(self)
        self.Htextbox.move(10, 170)
        self.Htextbox.resize(80,20)
        self.setWindowTitle("Sniff")
        self.layout= QtWidgets.QHBoxLayout()
        self.startbutton.resize(200,200)
        comboBox = QtWidgets.QComboBox(self)
        comboBox.addItem("ALL")
        comboBox.addItem("TCP")
        comboBox.addItem("UDP")
        comboBox.addItem("HTTP")
        comboBox.addItem("ICMP")
        comboBox.addItem("DNS")
        comboBox.addItem("SMTP")
        comboBox.addItem("FTP")
        comboBox.move(10,210)
        comboBox.resize(50,20)
        self.layout.addWidget(self.startbutton)
        self.setLayout(self.layout)
        self.scroll = QtWidgets.QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFixedHeight(400)
        self.scroll.setStyleSheet("background-color:black;")
        self.layout.addWidget(self.scroll)
        pal=self.palette()
        pal.setColor(self.backgroundRole(),QtCore.Qt.darkCyan)
        self.setPalette(pal)
        duration=""
        packets=[]
        def stopfilter(y,start_time,duration):
            timeDif=time.time()-start_time
            if(timeDif >= float(duration)):
                return True
            else:
                return False
            
        def startScan():
            host=self.Htextbox.text()
            duration=self.DTextBox.text()
            toru=str(comboBox.currentText())
            f=""
            if(len(host) >=1 and toru.lower != "all"):
                f=toru.lower()+" and host "+host
            elif(len(host) >= 1 and toru.lower()=="all"):
                f="host "+host
            elif(len(host) < 1 and toru.lower != "all"):
                f+=toru.lower()
            elif(len(host) < 1 and toru.lower == "all"):
                f=""
            print(f)
            start_time=time.time()
            sniff(filter=f,prn=lambda x:addpacket(x),stop_filter=lambda y:stopfilter(y,start_time,duration))

            self.hostlabel =QtWidgets.QLabel(self)
            self.hostlabel.setText("\n".join(packets))
            self.hostlabel.move(10,20)
            self.hostlabel.setStyleSheet('color:green;')
            self.scroll.setWidget(self.hostlabel)

        def addpacket(x):
            timestamp=time.time()
            local_time=time.localtime(timestamp)
            reg_time=time.asctime(local_time)
            packets.append(x.sprintf(reg_time+" {IP:%IP.src%:%TCP.sport% connected to %IP.dst%:%TCP.dport% WITH THE FLAGS: %TCP.flags% } "))
            
        self.startbutton.clicked.connect(startScan)

if __name__ == "__main__":
    app = QtWidgets.QApplication([])
    widget = GUI() 
    widget.resize(800,600)
    widget.setFixedSize(800,600)
    widget.show()
    sys.exit(app.exec_())



