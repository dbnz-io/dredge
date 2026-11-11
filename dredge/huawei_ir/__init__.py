from .config import HuaweiAuthConfig
from .hunt import HuaweiIRHunt
from .services import HuaweiServiceRegistry
from .secret_sweep import hunt_exposed_secrets_multi_profile
from .review import HuaweiIRReview
from .review_sweep import review_multi_profile


class HuaweiIRNamespace:
    def __init__(self, config: HuaweiAuthConfig, k8s_services=None):
        self.services = HuaweiServiceRegistry(config)
        self.hunt = HuaweiIRHunt(self.services, k8s_services=k8s_services)
        self.review = HuaweiIRReview(self.services)

    def close(self):
        self.services.close()
