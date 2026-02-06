import os, time, requests, chromadb, signal
from bcc import BPF
from colorama import Fore, Style, init

init(autoreset=True)
API_KEY = os.getenv("AI_AGENT_API_KEY")
SENSITIVE_PATHS = ["/etc/shadow", "/etc/passwd", ".ssh/", "/root/", "/etc/sudoers"]

# Inicializar Memoria Vectorial
chroma_client = chromadb.PersistentClient(path="./system_memory")
collection = chroma_client.get_or_create_collection(name="security_log")

def get_ai_decision(proc, detail, event_type):
    # 1. Consultar Memoria Histórica
    query_text = f"{proc} -> {detail}"
    past = collection.query(query_texts=[query_text], n_results=1)
    
    context = past['documents'][0][0] if past['documents'] else "Sin antecedentes."
    
    # 2. Inferencia Lógica
    prompt = f"""
    CONTEXTO: {context}
    EVENTO: El proceso '{proc}' realizó {detail}.
    TIPO: {'ACCESO ARCHIVO' if event_type == 2 else 'EJECUCION'}.
    Responde solo con una palabra: 
    - MALICIOUS (Si es una amenaza de seguridad)
    - LIMIT (Si consume demasiado pero es seguro)
    - SAFE (Si es normal)
    """
    
    try:
        r = requests.post("https://api.openai.com/v1/chat/completions", 
                         json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}], "max_tokens": 10},
                         headers={"Authorization": f"Bearer {API_KEY}"}, timeout=0.7)
        decision = r.json()['choices'][0]['message']['content'].strip().upper()
    except:
        decision = "SAFE" # Fallback conservador

    # 3. Guardar en Memoria para no repetir la consulta a la API
    collection.add(documents=[f"Resultado previo: {proc} haciendo {detail} fue {decision}"], ids=[str(time.time())])
    return decision

def handle_event(cpu, data, size):
    event = b["events"].event(data)
    proc = event.comm.decode('utf-8')
    pid = event.pid

    if proc in ["python3", "orchestrator.py"]: return

    if event.type == 1: # GESTIÓN DE RECURSOS
        decision = get_ai_decision(proc, "ejecución de programa", 1)
        if "LIMIT" in decision:
            os.system(f"renice -n 15 -p {pid} > /dev/null 2>&1")
            print(f"{Fore.YELLOW}[RECURSOS] {proc} limitado por historial.")

    elif event.type == 2: # SEGURIDAD ACTIVA
        path = event.filename.decode('utf-8')
        if any(p in path for p in SENSITIVE_PATHS):
            decision = get_ai_decision(proc, f"acceso a {path}", 2)
            if "MALICIOUS" in decision:
                os.kill(pid, signal.SIGKILL)
                print(f"{Fore.RED}[BLOQUEO] {proc} intentó acceder a {path}. PROCESO ELIMINADO.")

# Carga de Sensor
with open("sensor.c", "r") as f:
    b = BPF(text=f.read())
b.attach_kprobe(event="do_execve", fn_name="kprobe__do_execve")
b.attach_kprobe(event="do_sys_openat2", fn_name="kprobe__do_sys_openat2")

print(f"{Fore.CYAN}🛡️ SISTEMA CON MEMORIA ACTIVA Y SEGURIDAD INICIADO...{Style.RESET_ALL}")
b["events"].open_perf_buffer(handle_event)
while True: b.perf_buffer_poll()