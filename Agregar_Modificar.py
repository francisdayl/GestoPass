# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Modificar_Cuenta.ui'
#
# Created by: PyQt5 UI code generator 5.15.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.



from PyQt5 import QtCore, QtGui, QtWidgets
from funciones import *

class Ui_ModificarEditar_Cuenta(object):
    def setupUi(self, ModificarEditar_Cuenta,tipo,editar,datos):
        ModificarEditar_Cuenta.setObjectName("ModificarEditar_Cuenta")
        ModificarEditar_Cuenta.resize(354, 260)
        ModificarEditar_Cuenta.setWindowIcon(QtGui.QIcon("recursos/strong_doge.ico"))
        ModificarEditar_Cuenta.setMinimumSize(QtCore.QSize(300, 260))
        ModificarEditar_Cuenta.setMaximumSize(QtCore.QSize(800, 600))
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
        ModificarEditar_Cuenta.setPalette(palette)
        ModificarEditar_Cuenta.setStyleSheet("")
        self.centralwidget = QtWidgets.QWidget(ModificarEditar_Cuenta)
        self.centralwidget.setObjectName("centralwidget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.centralwidget)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.scrollArea = QtWidgets.QScrollArea(self.centralwidget)
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
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setObjectName("scrollArea")
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 277, 220))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
        self.formLayout_2 = QtWidgets.QFormLayout(self.scrollAreaWidgetContents)
        self.formLayout_2.setObjectName("formLayout_2")
        self.formLayout = QtWidgets.QFormLayout()
        self.formLayout.setObjectName("formLayout")
        self.formLayout_2.setLayout(0, QtWidgets.QFormLayout.LabelRole, self.formLayout)
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        self.horizontalLayout.addWidget(self.scrollArea)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.Boton_Agregar = QtWidgets.QPushButton(self.centralwidget)
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
        icon.addPixmap(QtGui.QPixmap("recursos/add_plataforma.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Boton_Agregar.setIcon(icon)
        self.Boton_Agregar.setIconSize(QtCore.QSize(45, 45))
        self.Boton_Agregar.setObjectName("Boton_Agregar")
        self.verticalLayout_2.addWidget(self.Boton_Agregar)
        self.Boton_Eliminar = QtWidgets.QPushButton(self.centralwidget)
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
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("recursos/delete_icon.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Boton_Eliminar.setIcon(icon1)
        self.Boton_Eliminar.setIconSize(QtCore.QSize(45, 45))
        self.Boton_Eliminar.setObjectName("Boton_Eliminar")
        self.verticalLayout_2.addWidget(self.Boton_Eliminar)
        self.Boton_Guardar = QtWidgets.QPushButton(self.centralwidget)
        self.Boton_Guardar.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.Boton_Guardar.setStyleSheet("QPushButton{\n"
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
        self.Boton_Guardar.setText("")
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap("recursos/guardar.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Boton_Guardar.setIcon(icon2)
        self.Boton_Guardar.setIconSize(QtCore.QSize(45, 45))
        self.Boton_Guardar.setObjectName("Boton_Guardar")
        self.verticalLayout_2.addWidget(self.Boton_Guardar)
        self.Boton_Regresar = QtWidgets.QPushButton(self.centralwidget)
        self.Boton_Regresar.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.Boton_Regresar.setStyleSheet("QPushButton{\n"
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
        self.Boton_Regresar.setText("")
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap("recursos/regresar.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Boton_Regresar.setIcon(icon3)
        self.Boton_Regresar.setIconSize(QtCore.QSize(45, 45))
        self.Boton_Regresar.setObjectName("Boton_Regresar")
        self.verticalLayout_2.addWidget(self.Boton_Regresar)
        self.horizontalLayout.addLayout(self.verticalLayout_2)
        ModificarEditar_Cuenta.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(ModificarEditar_Cuenta)
        self.statusbar.setObjectName("statusbar")
        ModificarEditar_Cuenta.setStatusBar(self.statusbar)

        self.retranslateUi(ModificarEditar_Cuenta)
        QtCore.QMetaObject.connectSlotsByName(ModificarEditar_Cuenta)
        self.Boton_Regresar.clicked.connect(lambda: ModificarEditar_Cuenta.destroy())
        self.Boton_Agregar.clicked.connect(self.agregar_campo)
        self.Boton_Eliminar.clicked.connect(self.eliminar_campo)
        self.Boton_Guardar.clicked.connect(self.guardar_datos)

        self.formLayout_2.setSpacing(15)
        
        Label_title1=QtWidgets.QLabel(text="Campo")
        Label_title1.setAlignment(QtCore.Qt.AlignCenter) 
        font = QtGui.QFont()
        font.setPointSize(13)
        font.setBold(True)
        Label_title1.setFont(font)
        Label_title2=QtWidgets.QLabel(text="Valor")
        Label_title2.setAlignment(QtCore.Qt.AlignCenter) 
        Label_title2.setFont(font)



        
        self.datos = datos#[]
        self.tipo = tipo

        self.formLayout_2.addRow(Label_title1,Label_title2)
        self.editar = editar
        if editar:
            self.rellenar_para_editar(self.get_tmp())  
        else:
            if self.tipo=="personal":
                if len(self.datos)==1:
                    self.misc_form()
                else:
                    self.base_form()
            elif self.tipo=="otros":
                if len(self.datos)==2:
                    self.misc_form()
                else:
                    self.base_form()

    def retranslateUi(self, ModificarEditar_Cuenta):
        _translate = QtCore.QCoreApplication.translate
        ModificarEditar_Cuenta.setWindowTitle(_translate("ModificarEditar_Cuenta", "Agregar/Modificar Cuenta"))

    def otras_cuentas(self):
        Seleccion_Cuenta = QtWidgets.QMainWindow()
        ui = Ui_Seleccion_Cuenta()
        ui.setupUi(Seleccion_Cuenta)
        Seleccion_Cuenta.show()

    def base_form(self):
        lista=["Plataforma","Correo","Usuario","Contraseña"]
        for c in lista:
            Label_auto=QtWidgets.QLabel(text=c)
            Label_auto.setAlignment(QtCore.Qt.AlignCenter) 

            font = QtGui.QFont()
            font.setPointSize(12)
            Label_auto.setFont(font)

            Text_entry = QtWidgets.QLineEdit() 
            Text_entry.setPlaceholderText(c)
            Text_entry.setFont(font)
            
            self.formLayout_2.addRow(Label_auto,Text_entry)
    
    def misc_form(self):
        Label_auto=QtWidgets.QLabel("Identificador")
        Label_auto.setAlignment(QtCore.Qt.AlignCenter) 
        font = QtGui.QFont()
        font.setPointSize(12)
        Label_auto.setFont(font)

        Text_entry = QtWidgets.QLineEdit() 
        Text_entry.setFont(font)
        Text_entry.setPlaceholderText("Valor")

        Text_entry2 = QtWidgets.QLineEdit() 
        Text_entry2.setFont(font)
        Text_entry2.setPlaceholderText("Campo")

        Text_entry3 = QtWidgets.QLineEdit() 
        Text_entry3.setFont(font)
        Text_entry3.setPlaceholderText("Valor")

        self.formLayout_2.addRow(Label_auto,Text_entry)
        self.formLayout_2.addRow(Text_entry2,Text_entry3)
        pass
        

    def agregar_campo(self):
        font = QtGui.QFont()
        font.setPointSize(12)

        Text_entry = QtWidgets.QLineEdit() 
        Text_entry.setFont(font)
        Text_entry.setPlaceholderText("Campo")
        Text_entry2 = QtWidgets.QLineEdit() 
        Text_entry2.setFont(font)
        Text_entry2.setPlaceholderText("Valor")

        self.formLayout_2.addRow(Text_entry,Text_entry2)

    def borrar_widgets(self,cant):
        if self.formLayout_2.count()>cant:
            for i in range(2):
                child = self.formLayout_2.takeAt(self.formLayout_2.count()-1)                        
                if child.widget():
                    child.widget().deleteLater()
        else:
            boton_error("No se pueden eliminar más campos")

    def eliminar_campo(self):
        minimo = 0
        if self.editar:
            if self.tipo=="personal":
                if len(self.datos)==1:
                    minimo = 5
                else:
                    minimo = 7
            else:
                if len(self.datos)==2:
                    minimo = 5
                else:
                    minimo = 7
        else: 
            if self.tipo=="personal":
                if len(self.datos)==1:
                    minimo = 7
                else:
                    minimo = 11
            else:
                if len(self.datos)==2:
                    minimo = 7
                else:
                    minimo = 11
        self.borrar_widgets(minimo)

    def rellenar_para_editar(self,diccio):
        for camp in list(diccio.keys()):
            font = QtGui.QFont()
            font.setPointSize(12)

            campo = QtWidgets.QLineEdit() 
            campo.setFont(font)
            campo.setPlaceholderText("Campo")
            campo.setText(camp)

            valor = QtWidgets.QLineEdit() 
            valor.setFont(font)
            valor.setPlaceholderText("Valor")
            valor.setText(diccio[camp])

            self.formLayout_2.addRow(campo,valor)
            pass

    def guardar_datos(self):
        n_dic = dict()
        for i in range(3,self.formLayout_2.count()-1,2):
            un_campo=self.formLayout_2.itemAt(i).widget().text().strip().title()
            un_valor=self.formLayout_2.itemAt(i+1).widget().text().strip()
            
            if len(un_campo)==0 or len(un_valor)==0:
                boton_error("Hay un campo vacío, revise los datos ingresados: ")
                n_dic = dict()
                break
            n_dic[un_campo]=un_valor
        if len(n_dic)==0:
            return None
        tmp_dic= cargar_tmp()        
        if self.editar:
            if self.tipo=="personal":
                if len(self.datos)==1:
                    tmp_dic["miscelaneo"][self.datos[0]] = n_dic
                else:
                    
                    tmp_dic["personal"][self.datos[0]][self.datos[1]] = n_dic
            else:
                if len(self.datos)==2:
                    tmp_dic["otros"][self.datos[0]]["miscelaneo"][self.datos[1]] = n_dic
                else:
                    tmp_dic["otros"][self.datos[0]]["personal"][self.datos[1]][self.datos[2]] = n_dic
            boton_info("Actualizacion Exitosa")
        else:
            if self.tipo=="personal":
                if len(self.datos)==1:
                    identf = n_dic["Identificador"]
                    del n_dic["Identificador"]
                    tmp_dic["miscelaneo"][identf] = n_dic
                else:
                    correo = n_dic["Correo"]
                    platf = n_dic["Plataforma"]
                    del n_dic["Correo"]
                    del n_dic["Plataforma"]   
                    if correo in tmp_dic["personal"]:        
                        tmp_dic["personal"][correo][platf]= n_dic
                    else:
                        tmp_dic["personal"][correo] = {platf: n_dic}
            elif self.tipo=="otros":
                if len(self.datos)==2:
                    identf = n_dic["Identificador"]
                    del n_dic["Identificador"]
                    tmp_dic["otros"][self.datos[0]]["miscelaneo"][identf]=n_dic
                else:
                    correo = n_dic["Correo"]
                    platf = n_dic["Plataforma"]
                    del n_dic["Correo"]
                    del n_dic["Plataforma"]     
                    if correo in tmp_dic["otros"][self.datos[0]]["personal"]:
                        tmp_dic["otros"][self.datos[0]]["personal"][correo][platf]= n_dic
                    else:
                        tmp_dic["otros"][self.datos[0]]["personal"][correo]= {platf:n_dic}
            boton_info("Registro exitoso")
        actualizar_tmp(tmp_dic)
        actualizar_con_tmp()
        self.Boton_Regresar.click()


    def get_tmp(self): 
        if self.editar:
            if self.tipo=="personal":
                if len(self.datos)==1:           
                    return cargar_tmp()["miscelaneo"][self.datos[0]]
                return cargar_tmp()["personal"][self.datos[0]][self.datos[1]]
            elif self.tipo=="otros":
                if len(self.datos)==2:           
                    return cargar_tmp()["otros"][self.datos[0]]["miscelaneo"][self.datos[1]]
                return cargar_tmp()["otros"][self.datos[0]]["personal"][self.datos[1]][self.datos[2]]
        else:
            if self.tipo=="personal":
                if len(self.datos)==1:           
                    return cargar_tmp()["miscelaneo"]
                return cargar_tmp()["personal"]
            elif self.tipo=="otros":
                if len(self.datos)==2:           
                    return cargar_tmp()["otros"][self.datos[0]]["miscelaneo"]
                return cargar_tmp()["otros"][self.datos[0]]["personal"]


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    ModificarEditar_Cuenta = QtWidgets.QMainWindow()
    ui = Ui_ModificarEditar_Cuenta()
    ui.setupUi(ModificarEditar_Cuenta,"otros",False,["correo@hotmail.com","xddd"])
    ModificarEditar_Cuenta.show()
    sys.exit(app.exec_())