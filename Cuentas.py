# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Cuentas.ui'
#
# Created by: PyQt5 UI code generator 5.15.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets
import pyperclip
from funciones import *
from functools import partial
from Agregar_Modificar import *


class Ui_Cuentas(object):
    def setupUi(self, Cuentas,tipo,otro):
        Cuentas.setObjectName("Cuentas")
        Cuentas.setEnabled(True)
        Cuentas.resize(515, 425)
        Cuentas.setWindowIcon(QtGui.QIcon("recursos/strong_doge.ico"))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(Cuentas.sizePolicy().hasHeightForWidth())
        Cuentas.setSizePolicy(sizePolicy)
        Cuentas.setMinimumSize(QtCore.QSize(515, 425))
        Cuentas.setMaximumSize(QtCore.QSize(515, 425))
        Cuentas.setBaseSize(QtCore.QSize(515, 464))
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
        Cuentas.setPalette(palette)
        self.centralwidget = QtWidgets.QWidget(Cuentas)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(50, 20, 161, 21))
        font = QtGui.QFont()
        font.setPointSize(11)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.Label_Correo = QtWidgets.QLabel(self.centralwidget)
        self.Label_Correo.setGeometry(QtCore.QRect(280, 20, 131, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.Label_Correo.setFont(font)
        self.Label_Correo.setObjectName("Label_Correo")
        self.Combo_Correos = QtWidgets.QComboBox(self.centralwidget)
        self.Combo_Correos.setGeometry(QtCore.QRect(260, 50, 161, 29))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.Combo_Correos.setFont(font)
        self.Combo_Correos.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.Combo_Correos.setEditable(False)
        self.Combo_Correos.setCurrentText("")
        self.Combo_Correos.setMaxVisibleItems(3)
        self.Combo_Correos.setObjectName("Combo_Correos")
        self.Label_Campo = QtWidgets.QLabel(self.centralwidget)
        self.Label_Campo.setGeometry(QtCore.QRect(10, 385, 491, 21))
        font = QtGui.QFont()
        font.setPointSize(11)
        font.setBold(True)
        font.setWeight(75)
        self.Label_Campo.setFont(font)
        self.Label_Campo.setFocusPolicy(QtCore.Qt.ClickFocus)
        self.Label_Campo.setAlignment(QtCore.Qt.AlignCenter)
        self.Label_Campo.setObjectName("Label_Campo")
        self.Boton_Agregar = QtWidgets.QPushButton(self.centralwidget)
        self.Boton_Agregar.setGeometry(QtCore.QRect(435, 20, 61, 61))
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
        menu = QtWidgets.QMenu()
        menu.addAction('Plataforma')
        menu.addSeparator()
        menu.addAction('Otro')
        menu.triggered.connect(self.agregar_cuenta)

        self.Boton_Agregar.setText("")
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("recursos/add_plataforma.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Boton_Agregar.setIcon(icon)
        self.Boton_Agregar.setIconSize(QtCore.QSize(42, 42))
        self.Boton_Agregar.setObjectName("Boton_Agregar")
        self.Boton_Agregar.setMenu(menu)
        self.Boton_Modificar = QtWidgets.QPushButton(self.centralwidget)
        self.Boton_Modificar.setGeometry(QtCore.QRect(435, 120, 61, 61))
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


        self.Boton_Actualizar = QtWidgets.QPushButton(self.centralwidget)
        self.Boton_Actualizar.setGeometry(QtCore.QRect(435, 220, 61, 61))
        self.Boton_Actualizar.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.Boton_Actualizar.setStyleSheet("QPushButton{\n"
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
        self.Boton_Actualizar.setText("")
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("recursos/recargar.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Boton_Actualizar.setIcon(icon1)
        self.Boton_Actualizar.setIconSize(QtCore.QSize(60, 60))
        self.Boton_Actualizar.setObjectName("Boton_Actualizar")



        self.Boton_Eliminar = QtWidgets.QPushButton(self.centralwidget)
        self.Boton_Eliminar.setGeometry(QtCore.QRect(435, 320, 61, 61))
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
        icon2.addPixmap(QtGui.QPixmap("recursos/delete_icon.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Boton_Eliminar.setIcon(icon2)
        self.Boton_Eliminar.setIconSize(QtCore.QSize(42, 42))
        self.Boton_Eliminar.setObjectName("Boton_Eliminar")

        

        self.scrollArea = QtWidgets.QScrollArea(self.centralwidget)
        self.scrollArea.setGeometry(QtCore.QRect(20, 150, 401, 221))
        palette = QtGui.QPalette()
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.WindowText, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Button, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Light, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Midlight, brush)
        brush = QtGui.QBrush(QtGui.QColor(127, 127, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Dark, brush)
        brush = QtGui.QBrush(QtGui.QColor(170, 170, 170))
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
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Window, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Shadow, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
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
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Button, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Light, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Midlight, brush)
        brush = QtGui.QBrush(QtGui.QColor(127, 127, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Dark, brush)
        brush = QtGui.QBrush(QtGui.QColor(170, 170, 170))
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
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Window, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Shadow, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.AlternateBase, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 220))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.ToolTipBase, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.ToolTipText, brush)
        brush = QtGui.QBrush(QtGui.QColor(127, 127, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.WindowText, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Button, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Light, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Midlight, brush)
        brush = QtGui.QBrush(QtGui.QColor(127, 127, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Dark, brush)
        brush = QtGui.QBrush(QtGui.QColor(170, 170, 170))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Mid, brush)
        brush = QtGui.QBrush(QtGui.QColor(127, 127, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Text, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.BrightText, brush)
        brush = QtGui.QBrush(QtGui.QColor(127, 127, 127))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.ButtonText, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Base, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Window, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Shadow, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.AlternateBase, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 220))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.ToolTipBase, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.ToolTipText, brush)
        self.scrollArea.setPalette(palette)
        font = QtGui.QFont()
        font.setPointSize(11)
        self.scrollArea.setFont(font)
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setObjectName("scrollArea")
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 399, 219))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.scrollAreaWidgetContents)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.Grid = QtWidgets.QGridLayout()
        self.Grid.setObjectName("Grid")
        self.gridLayout_2.addLayout(self.Grid, 0, 0, 1, 1)
        self.Grid.setColumnStretch(0,3)
        self.Grid.setColumnStretch(1,1)
        self.Grid.setColumnStretch(2,1)
        
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        self.Combo_Plats = QtWidgets.QComboBox(self.centralwidget)
        self.Combo_Plats.setGeometry(QtCore.QRect(28, 50, 191, 29))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.Combo_Plats.setFont(font)
        self.Combo_Plats.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.Combo_Plats.setEditable(True)
        self.Combo_Plats.setCurrentText("")
        self.Combo_Plats.setMaxVisibleItems(5)
        self.Combo_Plats.setObjectName("Combo_Plats")
        Cuentas.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(Cuentas)
        self.statusbar.setObjectName("statusbar")
        Cuentas.setStatusBar(self.statusbar)     
        self.retranslateUi(Cuentas)
        QtCore.QMetaObject.connectSlotsByName(Cuentas)
        self.otro = otro
        self.tipo = tipo

        #####Ventana Modificar agregar
        self.ModificarEditar_Cuenta = QtWidgets.QMainWindow()
        self.uiModificarEditar_Cuenta = Ui_ModificarEditar_Cuenta()
        self.hide_correos()
        self.llenar_combo()
        self.Combo_Plats.activated.connect(self.seleccion_plataforma)
        self.Combo_Correos.activated.connect(self.seleccion_correo)
        
        #self.Boton_Agregar.clicked.connect(self.agregar_cuenta)
        self.Boton_Modificar.clicked.connect(self.modificar_cuenta)
        self.Boton_Eliminar.clicked.connect(self.eliminar_cuenta)
        self.Boton_Actualizar.clicked.connect(self.llenar_combo)
        
        self.desactivar_bots_ctas(True)

        self.Label_Campo.clear()
        self.Grid.setVerticalSpacing(20)

 
    def retranslateUi(self, Cuentas):
        _translate = QtCore.QCoreApplication.translate
        Cuentas.setWindowTitle(_translate("Cuentas", "Cuentas"))
        self.label.setText(_translate("Cuentas", "Elija una plataforma"))
        self.Label_Correo.setText(_translate("Cuentas", "Seleccione Correo"))
        self.Label_Campo.setText(_translate("Cuentas", "El campo tal es: XXXXX"))

    def seleccion_correo(self):
        tmp = cargar_tmp()
        selec_corr =  self.Combo_Correos.currentText()
        select_plat = self.Combo_Plats.currentText()
        if self.tipo=="personal":
            self.llenar_grid(tmp["personal"][selec_corr][select_plat])
        else:
            self.llenar_grid(tmp["otros"][self.otro]["personal"][selec_corr][select_plat])

        self.desactivar_bots_ctas(False)


    def seleccion_plataforma(self):
        selec = self.Combo_Plats.currentText()
        tmp = cargar_tmp()
        self.clear_grid()
        if self.tipo=="personal":
            if selec in tmp["miscelaneo"]:
                self.llenar_grid(tmp["miscelaneo"][selec])
                self.desactivar_bots_ctas(False)
                self.Label_Correo.hide()
                self.Combo_Correos.hide()
                return None
            correos = get_correos_plataforma(tmp["personal"],selec)
            self.Label_Correo.show()
            if len(correos)>1:
                self.Combo_Correos.show()
                self.Label_Correo.show()
                self.Combo_Correos.addItems(correos) 
                self.desactivar_bots_ctas(True)
            else:               
                self.Combo_Correos.clear()
                self.Combo_Correos.addItems(correos)
                self.Combo_Correos.show()
                self.llenar_grid(tmp["personal"][correos[0]][selec])
                self.desactivar_bots_ctas(False)
                
        elif self.tipo=="otros":
            if selec in tmp["otros"][self.otro]["miscelaneo"]:
                self.llenar_grid(tmp["otros"][self.otro]["miscelaneo"][selec])
                self.desactivar_bots_ctas(False)
                self.Combo_Correos.hide()
                self.Label_Correo.hide()
                return None
            correos = get_correos_plataforma(tmp["otros"][self.otro]["personal"],selec)
            if len(correos)>1:
                self.Combo_Correos.show()
                self.Label_Correo.show()
                self.Combo_Correos.addItems(correos) 
                self.desactivar_bots_ctas(True)                            
            else:               
                self.Combo_Correos.clear()
                self.Combo_Correos.addItems(correos)
                self.Combo_Correos.show()
                self.Label_Correo.show()
                self.llenar_grid(tmp["otros"][self.otro]["personal"][correos[0]][selec])
                self.desactivar_bots_ctas(False)

    def clear_grid(self):
        while self.Grid.count():
            child = self.Grid.takeAt(0)                        
            if child.widget():
                    child.widget().deleteLater()
        return None

    def llenar_combo(self):
        self.Combo_Plats.clear()
        if self.tipo=="personal":
            self.Combo_Plats.addItems(get_plataformas(cargar_tmp()))
        else:
            self.Combo_Plats.addItems(get_plataformas(cargar_tmp()["otros"][self.otro]))
            

    def hide_correos(self):
        self.Label_Correo.hide()
        self.Combo_Correos.hide()
        
    def desactivar_bots_ctas(self,valor):
        self.Boton_Eliminar.setDisabled(valor)
        self.Boton_Modificar.setDisabled(valor)

    def llenar_grid(self,dic_dats):
        cont = 0
        for campo in list(dic_dats.keys()):
            Label_auto=QtWidgets.QLabel(text=campo)
            Label_auto.setAlignment(QtCore.Qt.AlignCenter)                
            self.Grid.addWidget(Label_auto,cont,0)

            boton_auto=QtWidgets.QPushButton()
            icono = QtGui.QIcon()
            icono.addPixmap(QtGui.QPixmap("recursos/eye.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
            boton_auto.setIcon(icono)
            boton_auto.setIconSize(QtCore.QSize(16, 16))
            boton_auto.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
            boton_auto.pressed.connect(partial(self.Label_Campo.setText,dic_dats[campo]))
            boton_auto.released.connect(lambda:self.Label_Campo.clear())
            self.Grid.addWidget(boton_auto,cont,1)

            boton_auto2=QtWidgets.QPushButton()
            icono2 = QtGui.QIcon()
            icono2.addPixmap(QtGui.QPixmap("recursos/copy.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
            boton_auto2.setIcon(icono2)
            boton_auto2.setIconSize(QtCore.QSize(16, 16))
            boton_auto2.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
            boton_auto2.pressed.connect(partial(self.Label_Campo.setText,"{} copiado!".format(campo)))
            boton_auto2.pressed.connect(partial(pyperclip.copy,dic_dats[campo]))
            boton_auto2.released.connect(lambda:self.Label_Campo.clear())
            self.Grid.addWidget(boton_auto2,cont,2)
            cont+=1
        pass

    def agregar_cuenta(self,selec):
        selec = selec.text()
        if selec=="Plataforma":
            if self.tipo=="personal":
                self.uiModificarEditar_Cuenta.setupUi(self.ModificarEditar_Cuenta,"personal",False,[])
                self.ModificarEditar_Cuenta.show()
            else:
                self.uiModificarEditar_Cuenta.setupUi(self.ModificarEditar_Cuenta,"otros",False,[self.otro])
                self.ModificarEditar_Cuenta.show()
        else:
            if self.tipo=="personal":
                self.uiModificarEditar_Cuenta.setupUi(self.ModificarEditar_Cuenta,"personal",False,["miscelaneo"])
                self.ModificarEditar_Cuenta.show()
            else:
                self.uiModificarEditar_Cuenta.setupUi(self.ModificarEditar_Cuenta,"otros",False,[self.otro,"miscelaneo"])
                self.ModificarEditar_Cuenta.show()


    
    def modificar_cuenta(self):
        selec = self.Combo_Plats.currentText()
        emails = get_correos_plataforma(self.get_tmp()["personal"],selec)
        if self.tipo=="personal":
            if len(emails)==0:
                self.uiModificarEditar_Cuenta.setupUi(self.ModificarEditar_Cuenta,"personal",True,[selec])
                self.ModificarEditar_Cuenta.show()
            elif len(emails)==1:
                self.uiModificarEditar_Cuenta.setupUi(self.ModificarEditar_Cuenta,"personal",True,[emails[0],selec])
                self.ModificarEditar_Cuenta.show()
            else:
                self.uiModificarEditar_Cuenta.setupUi(self.ModificarEditar_Cuenta,"personal",True,[self.Combo_Correos.currentText(),selec])
                self.ModificarEditar_Cuenta.show()
        else:
            if len(emails)==0:
                self.uiModificarEditar_Cuenta.setupUi(self.ModificarEditar_Cuenta,"otros",True,[self.otro,selec])
                self.ModificarEditar_Cuenta.show()
            elif len(emails)==1:
                self.uiModificarEditar_Cuenta.setupUi(self.ModificarEditar_Cuenta,"otros",True,[self.otro,emails[0],selec])
                self.ModificarEditar_Cuenta.show()
            else:
                self.uiModificarEditar_Cuenta.setupUi(self.ModificarEditar_Cuenta,"otros",True,[self.otro,self.Combo_Correos.currentText(),selec])
                self.ModificarEditar_Cuenta.show()
    
    def eliminar_cuenta(self):
        buttonReply = QtWidgets.QMessageBox.question(QtWidgets.QMessageBox(), 'Eliminar Cuenta', "Desea eliminar esta cuenta?", QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)
        if buttonReply == QtWidgets.QMessageBox.Yes:
            self.Combo_Correos.hide()
            self.Label_Correo.hide()
            tmp = cargar_tmp()
            platf_selec = self.Combo_Plats.currentText()
            if self.tipo=="personal":
                if platf_selec in tmp["miscelaneo"]:
                    del tmp["miscelaneo"][platf_selec]
                elif self.Combo_Correos.isHidden():
                    correo = get_correos_plataforma(tmp["personal"],platf_selec)[0]
                    del tmp["personal"][correo][platf_selec]
                else:
                    del tmp["personal"][self.Combo_Correos.currentText()][platf_selec]
                actualizar_tmp(tmp)
                self.clear_grid()
                self.llenar_combo()
                boton_info("Plataforma Eliminada Exitosamente")
            elif self.tipo=="otros":
                if platf_selec in tmp["otros"][self.otro]["miscelaneo"]:
                    del tmp["otros"][self.otro]["miscelaneo"][platf_selec]
                elif self.Combo_Correos.isHidden():
                    correo = get_correos_plataforma(tmp["otros"][self.otro]["personal"],platf_selec)[0]
                    del tmp["otros"][self.otro]["personal"][correo][platf_selec]
                else:
                    del tmp["otros"][self.otro]["personal"][self.Combo_Correos.currentText()][platf_selec]
                actualizar_tmp(tmp)
                self.clear_grid()
                self.llenar_combo()
                boton_info("Plataforma Eliminada Exitosamente")
    
    def get_tmp(self): 
        if self.tipo=="personal":
            return cargar_tmp()
        return cargar_tmp()["otros"][self.otro]

     


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Cuentas = QtWidgets.QMainWindow()
    ui = Ui_Cuentas()
    ui.setupUi(Cuentas,"personal",[])
    Cuentas.show()
    sys.exit(app.exec_())