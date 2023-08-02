import psutil
import time

def getProcessRunning(processName):
    processos = []
    '''
    Check if there is any running process that contains the given name processName.
    '''
    #Iterate over the all the running process
    for proc in psutil.process_iter():
        try:
            #print(proc)
        
            # Check if process name contains the given name string.
            if processName.lower() in proc.name().lower():
                dados = psutil.Process(proc.pid).cmdline()
                dados.append(round((time.time() - proc.create_time())/60,2))
                processos.append(dados)
                #print(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            print("err")
            pass

    return processos;


def teste():
    x = getProcessRunning("python")

    for proc in x:
        if "graficos.py" in proc[1]:
            print(proc)
            break

    x = getProcessRunning("auditoragent")
    if x: # processo encontrado
        print("AUditorAgent")

#teste()