from os import path,remove,urandom
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import time
from PyQt5 import QtCore, QtGui, QtWidgets
import pyperclip
import base64



if not path.exists("key.key"):
    key=Fernet.generate_key()
    file = open('key.key', 'wb')  
    file.write(key)  
    file.close()

def get_F():
    file = open('key.key', 'rb')  
    key = file.read()  
    file.close()
    F = Fernet(key)
    return F
    

def gen_key_pass(clave):
    password = clave.encode() 
    salt = b'P\xa2\x12\xa8\xfd\x9aY\xf5\xe15\xec\xea\xcaEpG'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=300,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def basic_encript(cade):
    F = get_F()
    return F.encrypt(cade.encode()).decode()


def basic_decript(cade):
    F = get_F()
    return F.decrypt(cade.encode()).decode()

######## "QUERIES" ##########
def cargar_db():
    archi = open("dats.xd","rb")
    F = get_F()
    dic_dec = eval(F.decrypt(archi.read()).decode()) 
    archi.close()
    return dic_dec

def guardar_act_db(dic):
    F = get_F()
    dic_enc = F.encrypt(str(dic).encode())
    open("dats.xd","wb").write(dic_enc)
    return None

def cargar_tmp():
    archi = open("temp.xd","rb")
    F = get_F()
    tmp = eval(F.decrypt(archi.read()).decode()) 
    archi.close()
    F_pass = Fernet(gen_key_pass(tmp["password"]))
    dic_info = eval(F_pass.decrypt(tmp["info"].encode()).decode())
    del tmp["info"]
    tmp.update(dic_info)
    return tmp

def actualizar_tmp(dic):
    info_tmp = {"personal":dic["personal"],"otros":dic["otros"],"miscelaneo":dic["miscelaneo"]}
    del dic["personal"]
    del dic["otros"]
    del dic["miscelaneo"]
    F_pas = Fernet(gen_key_pass(dic["password"]))
    dic["info"]=F_pas.encrypt(str(info_tmp).encode()).decode()
    F = get_F()
    open("temp.xd","wb").write(F.encrypt(str(dic).encode()))

def actualizar_con_tmp():
    archi = open("temp.xd","rb")
    F = get_F()
    tmp = eval(F.decrypt(archi.read()).decode()) 
    archi.close()      
    dic = cargar_db()      
    dic[get_last_user()]=tmp        
    guardar_act_db(dic)
    return None

def get_tiempo_actual():
    tiempo = time.localtime()
    return (tiempo[0],tiempo[1],tiempo[2],tiempo[3],tiempo[4],tiempo[5])

def new_user(usu,contra):
    dic_us = {"password":contra,"intentos":0,"ult_acces":get_tiempo_actual(),"pre_ult_acces":()}
    infor ={"personal":{},"otros":{},"miscelaneo":{}}
    F_pas = Fernet(gen_key_pass(contra))
    dic_us["info"]=F_pas.encrypt(str(infor).encode()).decode()
    F = get_F()
    if path.exists("dats.xd"):
        dic = cargar_db()
        dic[usu]=dic_us
        guardar_act_db(dic)
    else:
        guardar_act_db({usu:dic_us})
    return None

def log_last_user(usu):
    arch = open("last_user.log","w")
    arch.write(basic_encript(usu))
    arch.close()

def get_last_user():
    if path.exists("last_user.log"):
        arch = open("last_user.log","r")
        user = basic_decript(arch.readlines()[0].strip())
        arch.close()
        return user
    return None


############## Funciones ###############
def get_plataformas(dic):
    plataformas=set() 
    for cl in dic["personal"]:        
        plataformas = plataformas.union(set(list(dic["personal"][cl].keys())))
    plataformas = plataformas.union(set(list(dic["miscelaneo"].keys())))
    return list(plataformas)

def get_correos_plataforma(dic,plataforma):
    correos=[]
    for email in list(dic.keys()):
        if plataforma in list(dic[email].keys()):
            correos.append(email)
    return correos


def borr_tmp():
    if path.exists("temp.xd"):
        remove("temp.xd")
    if path.exists("last_user.log"):
        remove("last_user.log")
    return None

def get_time_dif(last_date,actual_date = time.localtime()):  
    year_dif = (actual_date[0]-last_date[0])*365*24*60*60
    month_dif = (actual_date[1]-last_date[1])*30*24*60*60
    day_dif = (actual_date[2]-last_date[2])*24*60*60
    hour_dif = (actual_date[3]-last_date[3])*60*60
    min_dif = (actual_date[4]-last_date[4])*60
    sec_dif = actual_date[5]-last_date[5]
    return year_dif+month_dif+day_dif+hour_dif+min_dif+sec_dif

def exportar(ruta):
    db_exp = cargar_tmp()
    F_pas = Fernet(gen_key_pass(db_exp["password"]))
    open(ruta,"wb").write(F_pas.encrypt(str(db_exp).encode()))

def importacion(ruta,clave):
    msj_err = "Archivo Denegado"
    try:
        archi = open(ruta,"rb")
        F = Fernet(gen_key_pass(clave))
        msj_err = "Clave Incorrecta"
        reg_imp = eval(F.decrypt(archi.read()).decode()) 
        archi.close() 
        tmp = cargar_tmp()
        #Si no estan actualizados el registro local
        if get_time_dif(reg_imp["ult_acces"],tmp["pre_ult_acces"])<1:
            tmp["personal"].update(reg_imp["personal"])
            tmp["miscelaneo"].update(reg_imp["miscelaneo"])
            tmp["otros"].update(reg_imp["otros"])
        else:
            pers_tmp = reg_imp["personal"]
            misc_tmp = reg_imp["miscelaneo"]
            otros_tmp = reg_imp["otros"]
            pers_tmp.update(tmp["personal"])
            misc_tmp.update(tmp["miscelaneo"])
            otros_tmp.update(tmp["otros"])
            tmp["personal"] = pers_tmp
            tmp["miscelaneo"] = misc_tmp
            tmp["otros"] = otros_tmp
        actualizar_tmp(tmp)
        actualizar_con_tmp()
        boton_info("Registros Importados Exitosamente!")    
    except:
        boton_error(msj_err)


def eliminar_usuario():
    dic = cargar_db()     
    del dic[get_last_user()]
    guardar_act_db(dic)

### Logeo

def valid_usu(usu):
    if path.exists("dats.xd"):
        dic = cargar_db()
        return usu in dic
    return False


def valid_usupass(usu,contra):
    db = cargar_db()
    dic_us = db[usu]
    log_last_user(usu)
    F = get_F()
    if dic_us["intentos"]>3 and ((((dic_us["intentos"]-3)**2)*15)-get_time_dif(dic_us["ult_acces"],time.localtime()))>0:       
       return (((dic_us["intentos"]-3)**2)*15)-get_time_dif(dic_us["ult_acces"],time.localtime())
    
    if dic_us["password"]==contra:
        dic_us["pre_ult_acces"]=dic_us["ult_acces"]
        dic_us["ult_acces"]=get_tiempo_actual()
        dic_us["intentos"]=0
        open("temp.xd","wb").write(F.encrypt(str(dic_us).encode()))
        log_last_user(usu)
        actualizar_con_tmp()
        return True
    
    dic_us["ult_acces"]=get_tiempo_actual()
    dic_us["intentos"]+=1
    db[usu] = dic_us
    guardar_act_db(db)
    return False 


def valid_login(usu,contra):
    if len(usu)<6 or len(contra)<8:
        return False
    if not valid_usu(usu):
        return False
    val = valid_usupass(usu,contra)
    if type(val)==int:
        return val
    return val


### Registro de usuario
def valid_usu_reg(usu):
    if valid_usu(usu):
        return "Usuario Inválido:\nEl usuario {} ya se encuentra registrado".format(usu)
    if len(usu)<5:
        return  "Usuario Inválido:\nEl nombre de usuario es muy corto"
    return True

def isStrongPass(cade):
    f_tam = len(cade)>6
    f_numb = False
    f_esp_char = False
    f_mayus = False
    f_minus = False
    for c in str(cade):
        if c.isdigit():
            f_numb = True
        elif c.islower():
            f_minus = True
        elif c.isupper():
            f_mayus = True
        elif not c.isalnum():
            f_esp_char = True
    if f_numb and f_esp_char and f_mayus and f_minus and f_tam:
        return True
    msj="La contraseña es insegura, para ser segura debe poseer:"
    if not f_tam:
        msj+="\nMás de 6 caracteres"
    if not f_numb:
        msj+="\nAlgún número"
    if not f_mayus:
        msj+="\nAlguna letra mayúscula"
    if not f_minus:
        msj+="\nAlguna letra minúscula"
    if not f_esp_char:
        msj+="\nAlgún caracter especial como: *, +, / , @, etc... "
    return msj
 

def boton_info(mensaje):
    boton = QtWidgets.QMessageBox()
    boton.setWindowTitle("Informacion")
    boton.setIcon(QtWidgets.QMessageBox.Information)
    boton.setText(mensaje)
    x = boton.exec_()

def boton_error(mensaje):
    boton = QtWidgets.QMessageBox()
    boton.setWindowTitle("Error")
    boton.setIcon(QtWidgets.QMessageBox.Critical)
    boton.setText(mensaje)
    x = boton.exec_() 

