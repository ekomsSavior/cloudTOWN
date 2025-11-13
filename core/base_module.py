# core/base_module.py
"""
Base class for all security testing modules
All modules must inherit from this class
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any

class BaseModule(ABC):
    """
    Abstract base class for all security modules
    """
    
    def __init__(self):
        self.name = ""
        self.description = ""
        self.category = ""  # discovery, exploitation, post_exploit
        self.platform = ""  # aws, azure, gcp, saas
        self.author = "ek0ms"
        self.version = "2.0"
    
    @abstractmethod
    def get_requirements(self) -> Dict[str, Dict[str, Any]]:
        """
        Return dictionary of required inputs from user
        
        Format:
        {
            'input_name': {
                'prompt': 'User prompt text',
                'type': 'text|password|choice|confirm',
                'default': 'default value',
                'choices': ['choice1', 'choice2'] (for type='choice')
            }
        }
        """
        pass
    
    @abstractmethod
    def validate_input(self, inputs: Dict[str, Any]) -> bool:
        """
        Validate user inputs before execution
        
        Args:
            inputs: Dictionary of user inputs
            
        Returns:
            bool: True if validation passes, False otherwise
        """
        pass
    
    @abstractmethod
    def scan(self, inputs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Discovery/scanning phase
        
        Args:
            inputs: Dictionary of validated user inputs
            
        Returns:
            List of discovered vulnerabilities/misconfigurations
        """
        pass
    
    @abstractmethod
    def exploit(self, targets: List[Dict[str, Any]], inputs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Exploitation phase
        
        Args:
            targets: List of targets from scan phase
            inputs: Original user inputs
            
        Returns:
            Dictionary containing exploitation results
        """
        pass
    
    def get_info(self) -> Dict[str, str]:
        """Get module information"""
        return {
            'name': self.name,
            'description': self.description,
            'category': self.category,
            'platform': self.platform,
            'author': self.author,
            'version': self.version
        }
