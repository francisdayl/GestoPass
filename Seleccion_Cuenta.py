# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Seleccion_Cuenta.ui'
#
# Created by: PyQt5 UI code generator 5.15.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets
from funciones import *
from Cuentas import *


class Ui_Seleccion_Cuenta(object):
    def setupUi(self, Seleccion_Cuenta):
        Seleccion_Cuenta.setObjectName("Seleccion_Cuenta")
        Seleccion_Cuenta.resize(480, 184)
        Seleccion_Cuenta.setWindowIcon(QtGui.QIcon("recursos/strong_doge.ico"))
        Seleccion_Cuenta.setMinimumSize(QtCore.QSize(480, 184))
        Seleccion_Cuenta.setMaximumSize(QtCore.QSize(480, 184))
        palette = QtGui.QPalette()
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.WindowText, brush)
        brush = QtGui.QBrush(QtGui.QColor(85, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Button, brush)
        brush = QtGui.QBrush(QtGui.QColor(213, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Light, brush)
        brush = QtGui.QBrush(QtGui.QColor(149, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Midlight, brush)
        brush = QtGui.QBrush(QtGui.QColor(42, 127, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Dark, brush)
        brush = QtGui.QBrush(QtGui.QColor(56, 170, 170))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Mid, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Text, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.BrightText, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.ButtonText, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Base, brush)
        brush = QtGui.QBrush(QtGui.QColor(85, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Window, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Shadow, brush)
        brush = QtGui.QBrush(QtGui.QColor(170, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.AlternateBase, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 220))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.ToolTipBase, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.ToolTipText, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.WindowText, brush)
        brush = QtGui.QBrush(QtGui.QColor(85, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Button, brush)
        brush = QtGui.QBrush(QtGui.QColor(213, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Light, brush)
        brush = QtGui.QBrush(QtGui.QColor(149, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Midlight, brush)
        brush = QtGui.QBrush(QtGui.QColor(42, 127, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Dark, brush)
        brush = QtGui.QBrush(QtGui.QColor(56, 170, 170))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Mid, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Text, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.BrightText, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.ButtonText, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Base, brush)
        brush = QtGui.QBrush(QtGui.QColor(85, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Window, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Shadow, brush)
        brush = QtGui.QBrush(QtGui.QColor(170, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.AlternateBase, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 220))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.ToolTipBase, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.ToolTipText, brush)
        brush = QtGui.QBrush(QtGui.QColor(42, 127, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.WindowText, brush)
        brush = QtGui.QBrush(QtGui.QColor(85, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Button, brush)
        brush = QtGui.QBrush(QtGui.QColor(213, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Light, brush)
        brush = QtGui.QBrush(QtGui.QColor(149, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Midlight, brush)
        brush = QtGui.QBrush(QtGui.QColor(42, 127, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Dark, brush)
        brush = QtGui.QBrush(QtGui.QColor(56, 170, 170))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Mid, brush)
        brush = QtGui.QBrush(QtGui.QColor(42, 127, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Text, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.BrightText, brush)
        brush = QtGui.QBrush(QtGui.QColor(42, 127, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.ButtonText, brush)
        brush = QtGui.QBrush(QtGui.QColor(85, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Base, brush)
        brush = QtGui.QBrush(QtGui.QColor(85, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Window, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Shadow, brush)
        brush = QtGui.QBrush(QtGui.QColor(85, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.AlternateBase, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 220))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.ToolTipBase, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.ToolTipText, brush)
        Seleccion_Cuenta.setPalette(palette)
        self.centralwidget = QtWidgets.QWidget(Seleccion_Cuenta)
        self.centralwidget.setObjectName("centralwidget")
        self.Combo_find = QtWidgets.QComboBox(self.centralwidget)
        self.Combo_find.setGeometry(QtCore.QRect(194, 15, 121, 25))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.Combo_find.setFont(font)
        self.Combo_find.setEditable(True)
        self.Combo_find.setMaxVisibleItems(5)
        self.Combo_find.setObjectName("Combo_find")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(10, 11, 181, 31))
        font = QtGui.QFont()
        font.setPointSize(11)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.Boton_Agregar = QtWidgets.QPushButton(self.centralwidget)
        self.Boton_Agregar.setGeometry(QtCore.QRect(330, 10, 51, 51))
        self.Boton_Agregar.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.Boton_Agregar.setStyleSheet("QPushButton{\n"
"    background-color: rgb(85, 255, 255);\n"
"    border: 1px rgb(65, 235, 235);\n"
"    padding-top: 5px;\n"
"    border-color: rgb(65, 235, 235);    \n"
"\n"
"    border-radius: 10px\n"
"    \n"
"    \n"
"}\n"
"QPushButton:hover{\n"
"    background-color: rgb(125, 255, 255);\n"
"    border -left: 1px solid rgb(110,144,76);\n"
"    border -right: 1px solid rgb(110,144,76);\n"
"    border -bottom: 5px solid rgb(110,144,76);    \n"
"     border-radius: 10px\n"
"}\n"
"QPushButton:pressed{\n"
"    background-color: rgb(65, 245, 245);\n"
"    padding-top: -5px;\n"
"    border -left: 1px solid rgb(110,144,76);\n"
"    border -right: 1px solid rgb(110,144,76);\n"
"    border -top: 5px solid rgb(110,144,76);    \n"
"    border -bottom:none;\n"
"    border-radius: 10px\n"
"} \n"
"")
        self.Boton_Agregar.setText("")
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("recursos/add_user.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Boton_Agregar.setIcon(icon)
        self.Boton_Agregar.setIconSize(QtCore.QSize(42, 42))
        self.Boton_Agregar.setObjectName("Boton_Agregar")
        self.Boton_Modificar = QtWidgets.QPushButton(self.centralwidget)
        self.Boton_Modificar.setGeometry(QtCore.QRect(410, 10, 51, 51))
        self.Boton_Modificar.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.Boton_Modificar.setStyleSheet("QPushButton{\n"
"    background-color: rgb(85, 255, 255);\n"
"    border: 1px rgb(65, 235, 235);\n"
"    padding-top: 5px;\n"
"    border-color: rgb(65, 235, 235);    \n"
"\n"
"    border-radius: 10px\n"
"    \n"
"    \n"
"}\n"
"QPushButton:hover{\n"
"    background-color: rgb(125, 255, 255);\n"
"    border -left: 1px solid rgb(110,144,76);\n"
"    border -right: 1px solid rgb(110,144,76);\n"
"    border -bottom: 5px solid rgb(110,144,76);    \n"
"     border-radius: 10px\n"
"}\n"
"QPushButton:pressed{\n"
"    background-color: rgb(65, 245, 245);\n"
"    padding-top: -5px;\n"
"    border -left: 1px solid rgb(110,144,76);\n"
"    border -right: 1px solid rgb(110,144,76);\n"
"    border -top: 5px solid rgb(110,144,76);    \n"
"    border -bottom:none;\n"
"    border-radius: 10px\n"
"} \n"
"")
        self.Boton_Modificar.setText("")
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("recursos/edit_icon.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Boton_Modificar.setIcon(icon1)
        self.Boton_Modificar.setIconSize(QtCore.QSize(42, 42))
        self.Boton_Modificar.setObjectName("Boton_Modificar")
        self.Boton_Eliminar = QtWidgets.QPushButton(self.centralwidget)
        self.Boton_Eliminar.setGeometry(QtCore.QRect(330, 74, 51, 51))
        self.Boton_Eliminar.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.Boton_Eliminar.setStyleSheet("QPushButton{\n"
"    background-color: rgb(85, 255, 255);\n"
"    border: 1px rgb(65, 235, 235);\n"
"    padding-top: 5px;\n"
"    border-color: rgb(65, 235, 235);    \n"
"\n"
"    border-radius: 10px\n"
"    \n"
"    \n"
"}\n"
"QPushButton:hover{\n"
"    background-color: rgb(125, 255, 255);\n"
"    border -left: 1px solid rgb(110,144,76);\n"
"    border -right: 1px solid rgb(110,144,76);\n"
"    border -bottom: 5px solid rgb(110,144,76);    \n"
"     border-radius: 10px\n"
"}\n"
"QPushButton:pressed{\n"
"    background-color: rgb(65, 245, 245);\n"
"    padding-top: -5px;\n"
"    border -left: 1px solid rgb(110,144,76);\n"
"    border -right: 1px solid rgb(110,144,76);\n"
"    border -top: 5px solid rgb(110,144,76);    \n"
"    border -bottom:none;\n"
"    border-radius: 10px\n"
"} \n"
"")
        self.Boton_Eliminar.setText("")
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap("recursos/delete_user.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Boton_Eliminar.setIcon(icon2)
        self.Boton_Eliminar.setIconSize(QtCore.QSize(42, 42))
        self.Boton_Eliminar.setObjectName("Boton_Eliminar")
        self.Boton_Buscar = QtWidgets.QPushButton(self.centralwidget)
        self.Boton_Buscar.setGeometry(QtCore.QRect(410, 74, 51, 51))
        self.Boton_Buscar.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.Boton_Buscar.setStyleSheet("QPushButton{\n"
"    background-color: rgb(85, 255, 255);\n"
"    border: 1px rgb(65, 235, 235);\n"
"    padding-top: 5px;\n"
"    border-color: rgb(65, 235, 235);    \n"
"\n"
"    border-radius: 10px\n"
"    \n"
"    \n"
"}\n"
"QPushButton:hover{\n"
"    background-color: rgb(125, 255, 255);\n"
"    border -left: 1px solid rgb(110,144,76);\n"
"    border -right: 1px solid rgb(110,144,76);\n"
"    border -bottom: 5px solid rgb(110,144,76);    \n"
"     border-radius: 10px\n"
"}\n"
"QPushButton:pressed{\n"
"    background-color: rgb(65, 245, 245);\n"
"    padding-top: -5px;\n"
"    border -left: 1px solid rgb(110,144,76);\n"
"    border -right: 1px solid rgb(110,144,76);\n"
"    border -top: 5px solid rgb(110,144,76);    \n"
"    border -bottom:none;\n"
"    border-radius: 10px\n"
"} \n"
"")
        self.Boton_Buscar.setText("")
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap("recursos/search.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Boton_Buscar.setIcon(icon3)
        self.Boton_Buscar.setIconSize(QtCore.QSize(42, 42))
        self.Boton_Buscar.setObjectName("Boton_Buscar")
        self.Label_Nombres = QtWidgets.QLabel(self.centralwidget)
        self.Label_Nombres.setGeometry(QtCore.QRect(30, 90, 80, 21))
        font = QtGui.QFont()
        font.setPointSize(11)
        font.setBold(True)
        font.setWeight(75)
        self.Label_Nombres.setFont(font)
        self.Label_Nombres.setObjectName("Label_Nombres")
        self.Label_Id = QtWidgets.QLabel(self.centralwidget)
        self.Label_Id.setGeometry(QtCore.QRect(30, 130, 71, 21))
        font = QtGui.QFont()
        font.setPointSize(11)
        font.setBold(True)
        font.setWeight(75)
        self.Label_Id.setFont(font)
        self.Label_Id.setObjectName("Label_Id")
        self.Text_Nombres = QtWidgets.QLineEdit(self.centralwidget)
        self.Text_Nombres.setGeometry(QtCore.QRect(130, 90, 181, 21))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.Text_Nombres.setFont(font)
        self.Text_Nombres.setObjectName("Text_Nombres")
        self.Text_Nombres.setPlaceholderText("Ingrese nombres*")
        self.Text_Id = QtWidgets.QLineEdit(self.centralwidget)
        self.Text_Id.setGeometry(QtCore.QRect(130, 130, 181, 21))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.Text_Id.setFont(font)
        self.Text_Id.setObjectName("Text_Id")
        self.Text_Id.setPlaceholderText("Ingrese ID")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(355, 134, 91, 31))
        self.pushButton.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.pushButton.setObjectName("pushButton")
        Seleccion_Cuenta.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(Seleccion_Cuenta)
        self.statusbar.setObjectName("statusbar")
        Seleccion_Cuenta.setStatusBar(self.statusbar)

        self.retranslateUi(Seleccion_Cuenta)
        QtCore.QMetaObject.connectSlotsByName(Seleccion_Cuenta)

        
        self.rellenar_combo()
        self.Combo_find.activated.connect(self.seleccionado)

        self.desactivar_bots(True)
        self.pushButton.clicked.connect(lambda: Seleccion_Cuenta.destroy())
        self.Boton_Agregar.clicked.connect(self.agregar_usuario)
        self.Boton_Eliminar.clicked.connect(self.eliminar_usuario)
        self.Boton_Modificar.clicked.connect(self.editar_usuario)
        self.Boton_Buscar.clicked.connect(self.buscar_usuario)

        #Ventana Cuenta
        self.Cuentas = QtWidgets.QMainWindow()
        self.ui_Cuentas = Ui_Cuentas()
          

    def retranslateUi(self, Seleccion_Cuenta):
        _translate = QtCore.QCoreApplication.translate
        Seleccion_Cuenta.setWindowTitle(_translate("Seleccion_Cuenta", "Seleccion de Cuenta"))
        self.label.setText(_translate("Seleccion_Cuenta", "Seleccione ID o Nombre"))
        self.Label_Nombres.setText(_translate("Seleccion_Cuenta", "Nombres*"))
        self.Label_Id.setText(_translate("Seleccion_Cuenta", "ID"))
        self.pushButton.setText(_translate("Seleccion_Cuenta", "Regresar"))

    def desactivar_bots(self,val):
        self.Boton_Buscar.setDisabled(val)
        self.Boton_Eliminar.setDisabled(val)
        self.Boton_Modificar.setDisabled(val)

    def limpiar_text(self):        
        self.Text_Id.clear()
        self.Text_Nombres.clear()


    def get_id_nombre(self,val):
        tmp = cargar_tmp()
        if val in list(tmp["otros"].keys()):
            return [val,tmp["otros"][val]["id"]]
        else:
            for users in list(tmp["otros"].keys()):
                id_us = tmp["otros"][users]["id"]
                if val==id_us:
                    return [users,val]


    def seleccionado(self):
        selec = self.Combo_find.currentText()
        nomb, id_nom = self.get_id_nombre(selec)
        self.Text_Nombres.setText(nomb)
        self.Text_Id.setText(id_nom)
        self.desactivar_bots(False)

    def eliminar_usuario(self):
        buttonReply = QtWidgets.QMessageBox.question(QtWidgets.QMessageBox(), 'Eliminar Usuario', "Desea Eiminar este usuario y todas las cuentas asociadas?", QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)
        if buttonReply == QtWidgets.QMessageBox.Yes: 
            nomb, id_nomb = self.get_id_nombre(self.Combo_find.currentText()) 
            tmp = cargar_tmp()
            del tmp["otros"][nomb]
            actualizar_tmp(tmp)
            actualizar_con_tmp()
            boton_info("Usuario Eliminado Exitosamente!")
            self.limpiar_text()
            self.rellenar_combo()

    def rellenar_combo(self):
        tmp = cargar_tmp()
        lis_us_id=[]
        users = list(tmp ["otros"].keys())
        for us in users:
            lis_us_id.append(us)
            id_us = tmp["otros"][us]["id"]
            if len(id_us)>3:
                lis_us_id.append(id_us)
        self.Combo_find.clear()
        self.Combo_find.addItems(lis_us_id)
        return None

    def editar_usuario(self):
        nomb, id_nomb = self.get_id_nombre(self.Combo_find.currentText())
        tmp = cargar_tmp()
        tmp["otros"][nomb]["id"]=self.Text_Id.text().strip()
        actualizar_tmp(tmp)
        actualizar_con_tmp()
        boton_info("Usuario Editado!")
        self.rellenar_combo()
        self.limpiar_text()



    def agregar_usuario(self):
        
        ident = self.Text_Id.text().strip()
        nombs = self.Text_Nombres.text().strip()
        if len(nombs)<3:
                boton_error("Nombre inválido, corrija dicho campo")
                return None
        tmp = cargar_tmp()
        tmp["otros"][nombs]={"nombres":nombs,"id":ident,"personal":{},"miscelaneo":{}}
        actualizar_tmp(tmp)
        actualizar_con_tmp()
        boton_info("Usuario agregado exitosamente!")
        self.limpiar_text()
        self.desactivar_bots(True)
        self.rellenar_combo()
     
    def buscar_usuario(self):
        nomb, id_nom = self.get_id_nombre(self.Combo_find.currentText())
        self.ui_Cuentas.setupUi(self.Cuentas,"otros",nomb)
        self.Cuentas.show() 



if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Seleccion_Cuenta = QtWidgets.QMainWindow()
    ui = Ui_Seleccion_Cuenta()
    ui.setupUi(Seleccion_Cuenta)
    Seleccion_Cuenta.show()
    sys.exit(app.exec_())
