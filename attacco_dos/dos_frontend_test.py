from locust import HttpUser, task, between

class FrontendDoSAttacker(HttpUser):
    # Nessun tempo di attesa: attacco al massimo della velocità
    wait_time = between(0.1, 0.3)

    @task
    def load_dashboard(self):
        # Facciamo una semplice richiesta GET alla radice del frontend
        # Questo costringe il server a caricare l'interfaccia senza inviare dati al backend
        self.client.get("/")