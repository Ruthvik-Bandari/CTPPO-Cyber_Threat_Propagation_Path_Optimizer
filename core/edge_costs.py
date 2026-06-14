"""
Edge Cost Definitions with Probability Distributions
=====================================================

This module defines multi-dimensional edge costs for attack graph edges.
Each edge carries a cost vector that may include:
- Time-to-exploit (τ): Time required to execute the attack step
- Success probability (p): Probability of attacker success
- Business impact (ι): Contribution to business impact
- Detection probability (d): Probability of being detected

Costs can be modeled as:
- Fixed scalars
- Probability distributions (for uncertainty modeling)
- Time-varying functions

Author: Ruthvik
Date: November 2025
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union, Callable
from enum import Enum, auto
import numpy as np
from scipy import stats
import uuid


class CostType(Enum):
    """Types of cost components"""
    TIME_TO_EXPLOIT = auto()
    SUCCESS_PROBABILITY = auto()
    BUSINESS_IMPACT = auto()
    DETECTION_PROBABILITY = auto()
    SKILL_REQUIREMENT = auto()
    RESOURCE_COST = auto()


class AggregationType(Enum):
    """How costs aggregate along a path"""
    SUM = "sum"              # Total time = sum of edge times
    PRODUCT = "product"      # Total probability = product of edge probabilities
    MAX = "max"              # Maximum impact along path
    MIN = "min"              # Minimum (e.g., bottleneck)
    WEIGHTED_SUM = "weighted_sum"


class DistributionType(Enum):
    """Types of probability distributions"""
    CONSTANT = "constant"
    NORMAL = "normal"
    LOGNORMAL = "lognormal"
    EXPONENTIAL = "exponential"
    UNIFORM = "uniform"
    TRIANGULAR = "triangular"
    BETA = "beta"
    GAMMA = "gamma"
    PERT = "pert"  # Common in risk analysis


@dataclass
class Distribution(ABC):
    """Abstract base class for probability distributions"""
    
    @abstractmethod
    def sample(self, n: int = 1) -> np.ndarray:
        """Draw n samples from the distribution"""
        pass
    
    @abstractmethod
    def mean(self) -> float:
        """Return the mean of the distribution"""
        pass
    
    @abstractmethod
    def variance(self) -> float:
        """Return the variance of the distribution"""
        pass
    
    @abstractmethod
    def cdf(self, x: float) -> float:
        """Cumulative distribution function"""
        pass
    
    @abstractmethod
    def pdf(self, x: float) -> float:
        """Probability density function"""
        pass
    
    @abstractmethod
    def quantile(self, p: float) -> float:
        """Return the p-th quantile"""
        pass
    
    def std(self) -> float:
        """Return the standard deviation"""
        return np.sqrt(self.variance())
    
    def confidence_interval(self, confidence: float = 0.95) -> Tuple[float, float]:
        """Return confidence interval"""
        alpha = 1 - confidence
        return (self.quantile(alpha / 2), self.quantile(1 - alpha / 2))
    
    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        pass
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'Distribution':
        """Deserialize from dictionary"""
        dist_type = DistributionType(data["type"])
        
        type_mapping = {
            DistributionType.CONSTANT: ConstantDistribution,
            DistributionType.NORMAL: NormalDistribution,
            DistributionType.LOGNORMAL: LogNormalDistribution,
            DistributionType.EXPONENTIAL: ExponentialDistribution,
            DistributionType.UNIFORM: UniformDistribution,
            DistributionType.TRIANGULAR: TriangularDistribution,
            DistributionType.BETA: BetaDistribution,
            DistributionType.GAMMA: GammaDistribution,
            DistributionType.PERT: PERTDistribution
        }
        
        return type_mapping[dist_type].from_dict(data)


@dataclass
class ConstantDistribution(Distribution):
    """Deterministic (constant) value"""
    value: float = 0.0
    
    def sample(self, n: int = 1) -> np.ndarray:
        return np.full(n, self.value)
    
    def mean(self) -> float:
        return self.value
    
    def variance(self) -> float:
        return 0.0
    
    def cdf(self, x: float) -> float:
        return 1.0 if x >= self.value else 0.0
    
    def pdf(self, x: float) -> float:
        return float('inf') if x == self.value else 0.0
    
    def quantile(self, p: float) -> float:
        return self.value
    
    def to_dict(self) -> Dict[str, Any]:
        return {"type": DistributionType.CONSTANT.value, "value": self.value}
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'ConstantDistribution':
        return ConstantDistribution(value=data["value"])


@dataclass
class NormalDistribution(Distribution):
    """Normal (Gaussian) distribution"""
    mu: float = 0.0
    sigma: float = 1.0
    
    def __post_init__(self):
        self._dist = stats.norm(loc=self.mu, scale=self.sigma)
    
    def sample(self, n: int = 1) -> np.ndarray:
        return self._dist.rvs(size=n)
    
    def mean(self) -> float:
        return self.mu
    
    def variance(self) -> float:
        return self.sigma ** 2
    
    def cdf(self, x: float) -> float:
        return self._dist.cdf(x)
    
    def pdf(self, x: float) -> float:
        return self._dist.pdf(x)
    
    def quantile(self, p: float) -> float:
        return self._dist.ppf(p)
    
    def to_dict(self) -> Dict[str, Any]:
        return {"type": DistributionType.NORMAL.value, "mu": self.mu, "sigma": self.sigma}
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'NormalDistribution':
        return NormalDistribution(mu=data["mu"], sigma=data["sigma"])


@dataclass
class LogNormalDistribution(Distribution):
    """Log-normal distribution - good for time-to-exploit modeling"""
    mu: float = 0.0  # Mean of the underlying normal
    sigma: float = 1.0  # Std of the underlying normal
    
    def __post_init__(self):
        self._dist = stats.lognorm(s=self.sigma, scale=np.exp(self.mu))
    
    def sample(self, n: int = 1) -> np.ndarray:
        return self._dist.rvs(size=n)
    
    def mean(self) -> float:
        return np.exp(self.mu + self.sigma**2 / 2)
    
    def variance(self) -> float:
        return (np.exp(self.sigma**2) - 1) * np.exp(2*self.mu + self.sigma**2)
    
    def cdf(self, x: float) -> float:
        return self._dist.cdf(x)
    
    def pdf(self, x: float) -> float:
        return self._dist.pdf(x)
    
    def quantile(self, p: float) -> float:
        return self._dist.ppf(p)
    
    def to_dict(self) -> Dict[str, Any]:
        return {"type": DistributionType.LOGNORMAL.value, "mu": self.mu, "sigma": self.sigma}
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'LogNormalDistribution':
        return LogNormalDistribution(mu=data["mu"], sigma=data["sigma"])


@dataclass
class ExponentialDistribution(Distribution):
    """Exponential distribution - memoryless property useful for attack timing"""
    rate: float = 1.0  # λ (rate parameter)
    
    def __post_init__(self):
        self._dist = stats.expon(scale=1/self.rate)
    
    def sample(self, n: int = 1) -> np.ndarray:
        return self._dist.rvs(size=n)
    
    def mean(self) -> float:
        return 1 / self.rate
    
    def variance(self) -> float:
        return 1 / (self.rate ** 2)
    
    def cdf(self, x: float) -> float:
        return self._dist.cdf(x)
    
    def pdf(self, x: float) -> float:
        return self._dist.pdf(x)
    
    def quantile(self, p: float) -> float:
        return self._dist.ppf(p)
    
    def to_dict(self) -> Dict[str, Any]:
        return {"type": DistributionType.EXPONENTIAL.value, "rate": self.rate}
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'ExponentialDistribution':
        return ExponentialDistribution(rate=data["rate"])


@dataclass
class UniformDistribution(Distribution):
    """Uniform distribution"""
    low: float = 0.0
    high: float = 1.0
    
    def __post_init__(self):
        self._dist = stats.uniform(loc=self.low, scale=self.high - self.low)
    
    def sample(self, n: int = 1) -> np.ndarray:
        return self._dist.rvs(size=n)
    
    def mean(self) -> float:
        return (self.low + self.high) / 2
    
    def variance(self) -> float:
        return (self.high - self.low) ** 2 / 12
    
    def cdf(self, x: float) -> float:
        return self._dist.cdf(x)
    
    def pdf(self, x: float) -> float:
        return self._dist.pdf(x)
    
    def quantile(self, p: float) -> float:
        return self._dist.ppf(p)
    
    def to_dict(self) -> Dict[str, Any]:
        return {"type": DistributionType.UNIFORM.value, "low": self.low, "high": self.high}
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'UniformDistribution':
        return UniformDistribution(low=data["low"], high=data["high"])


@dataclass
class TriangularDistribution(Distribution):
    """Triangular distribution - useful for expert estimates"""
    low: float = 0.0
    mode: float = 0.5
    high: float = 1.0
    
    def __post_init__(self):
        c = (self.mode - self.low) / (self.high - self.low)
        self._dist = stats.triang(c, loc=self.low, scale=self.high - self.low)
    
    def sample(self, n: int = 1) -> np.ndarray:
        return self._dist.rvs(size=n)
    
    def mean(self) -> float:
        return (self.low + self.mode + self.high) / 3
    
    def variance(self) -> float:
        return (self.low**2 + self.mode**2 + self.high**2 
                - self.low*self.mode - self.low*self.high - self.mode*self.high) / 18
    
    def cdf(self, x: float) -> float:
        return self._dist.cdf(x)
    
    def pdf(self, x: float) -> float:
        return self._dist.pdf(x)
    
    def quantile(self, p: float) -> float:
        return self._dist.ppf(p)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": DistributionType.TRIANGULAR.value,
            "low": self.low, "mode": self.mode, "high": self.high
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'TriangularDistribution':
        return TriangularDistribution(low=data["low"], mode=data["mode"], high=data["high"])


@dataclass
class BetaDistribution(Distribution):
    """Beta distribution - useful for modeling probabilities"""
    alpha: float = 2.0
    beta: float = 2.0
    
    def __post_init__(self):
        self._dist = stats.beta(self.alpha, self.beta)
    
    def sample(self, n: int = 1) -> np.ndarray:
        return self._dist.rvs(size=n)
    
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)
    
    def variance(self) -> float:
        ab = self.alpha + self.beta
        return (self.alpha * self.beta) / (ab**2 * (ab + 1))
    
    def cdf(self, x: float) -> float:
        return self._dist.cdf(x)
    
    def pdf(self, x: float) -> float:
        return self._dist.pdf(x)
    
    def quantile(self, p: float) -> float:
        return self._dist.ppf(p)
    
    def to_dict(self) -> Dict[str, Any]:
        return {"type": DistributionType.BETA.value, "alpha": self.alpha, "beta": self.beta}
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'BetaDistribution':
        return BetaDistribution(alpha=data["alpha"], beta=data["beta"])


@dataclass
class GammaDistribution(Distribution):
    """Gamma distribution - useful for waiting times"""
    shape: float = 2.0  # k (shape parameter)
    scale: float = 1.0  # θ (scale parameter)
    
    def __post_init__(self):
        self._dist = stats.gamma(self.shape, scale=self.scale)
    
    def sample(self, n: int = 1) -> np.ndarray:
        return self._dist.rvs(size=n)
    
    def mean(self) -> float:
        return self.shape * self.scale
    
    def variance(self) -> float:
        return self.shape * self.scale ** 2
    
    def cdf(self, x: float) -> float:
        return self._dist.cdf(x)
    
    def pdf(self, x: float) -> float:
        return self._dist.pdf(x)
    
    def quantile(self, p: float) -> float:
        return self._dist.ppf(p)
    
    def to_dict(self) -> Dict[str, Any]:
        return {"type": DistributionType.GAMMA.value, "shape": self.shape, "scale": self.scale}
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'GammaDistribution':
        return GammaDistribution(shape=data["shape"], scale=data["scale"])


@dataclass
class PERTDistribution(Distribution):
    """
    PERT (Program Evaluation and Review Technique) distribution.
    Commonly used in risk analysis and project management.
    A modified beta distribution with min, most likely, and max values.
    """
    minimum: float = 0.0
    most_likely: float = 5.0
    maximum: float = 10.0
    lambd: float = 4.0  # Shape parameter (default 4 for standard PERT)
    
    def __post_init__(self):
        # Calculate beta distribution parameters
        mean = (self.minimum + self.lambd * self.most_likely + self.maximum) / (self.lambd + 2)
        
        # Handle edge cases
        if self.maximum == self.minimum:
            self._is_constant = True
            self._value = self.minimum
        else:
            self._is_constant = False
            # Calculate alpha and beta for beta distribution
            if mean == self.most_likely:
                alpha = beta = 1 + self.lambd / 2
            else:
                alpha = ((mean - self.minimum) * (2 * self.most_likely - self.minimum - self.maximum) /
                        ((self.most_likely - mean) * (self.maximum - self.minimum)))
                beta = alpha * (self.maximum - mean) / (mean - self.minimum)
            
            # Ensure positive parameters
            alpha = max(0.1, alpha)
            beta = max(0.1, beta)
            
            self._alpha = alpha
            self._beta = beta
            self._dist = stats.beta(alpha, beta, 
                                   loc=self.minimum, 
                                   scale=self.maximum - self.minimum)
    
    def sample(self, n: int = 1) -> np.ndarray:
        if self._is_constant:
            return np.full(n, self._value)
        return self._dist.rvs(size=n)
    
    def mean(self) -> float:
        return (self.minimum + self.lambd * self.most_likely + self.maximum) / (self.lambd + 2)
    
    def variance(self) -> float:
        mean = self.mean()
        return ((mean - self.minimum) * (self.maximum - mean)) / (self.lambd + 3)
    
    def cdf(self, x: float) -> float:
        if self._is_constant:
            return 1.0 if x >= self._value else 0.0
        return self._dist.cdf(x)
    
    def pdf(self, x: float) -> float:
        if self._is_constant:
            return float('inf') if x == self._value else 0.0
        return self._dist.pdf(x)
    
    def quantile(self, p: float) -> float:
        if self._is_constant:
            return self._value
        return self._dist.ppf(p)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": DistributionType.PERT.value,
            "minimum": self.minimum,
            "most_likely": self.most_likely,
            "maximum": self.maximum,
            "lambd": self.lambd
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'PERTDistribution':
        return PERTDistribution(
            minimum=data["minimum"],
            most_likely=data["most_likely"],
            maximum=data["maximum"],
            lambd=data.get("lambd", 4.0)
        )


@dataclass
class CostComponent:
    """
    A single cost component (e.g., time, probability, impact).
    
    Attributes:
        cost_type: Type of cost (time, probability, etc.)
        distribution: Probability distribution of the cost
        aggregation: How this cost aggregates along a path
        weight: Weight for multi-objective optimization
        bounds: Optional (min, max) bounds for the cost
    """
    cost_type: CostType
    distribution: Distribution
    aggregation: AggregationType = AggregationType.SUM
    weight: float = 1.0
    bounds: Optional[Tuple[float, float]] = None
    name: str = ""
    unit: str = ""
    
    def sample(self, n: int = 1) -> np.ndarray:
        """Sample from the cost distribution"""
        samples = self.distribution.sample(n)
        if self.bounds:
            samples = np.clip(samples, self.bounds[0], self.bounds[1])
        return samples
    
    def expected_value(self) -> float:
        """Get expected (mean) value"""
        return self.distribution.mean()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "cost_type": self.cost_type.name,
            "distribution": self.distribution.to_dict(),
            "aggregation": self.aggregation.value,
            "weight": self.weight,
            "bounds": self.bounds,
            "name": self.name,
            "unit": self.unit
        }


@dataclass
class EdgeCostVector:
    """
    Multi-dimensional cost vector for an edge.
    
    Contains multiple cost components that are tracked separately
    for multi-objective optimization.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    components: Dict[CostType, CostComponent] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def create_default(cls) -> 'EdgeCostVector':
        """Create a default cost vector with standard components"""
        return cls(
            components={
                CostType.TIME_TO_EXPLOIT: CostComponent(
                    cost_type=CostType.TIME_TO_EXPLOIT,
                    distribution=LogNormalDistribution(mu=1.0, sigma=0.5),
                    aggregation=AggregationType.SUM,
                    weight=1.0,
                    name="Time to Exploit",
                    unit="hours"
                ),
                CostType.SUCCESS_PROBABILITY: CostComponent(
                    cost_type=CostType.SUCCESS_PROBABILITY,
                    distribution=BetaDistribution(alpha=8, beta=2),
                    aggregation=AggregationType.PRODUCT,
                    weight=1.0,
                    bounds=(0.0, 1.0),
                    name="Success Probability",
                    unit="probability"
                ),
                CostType.BUSINESS_IMPACT: CostComponent(
                    cost_type=CostType.BUSINESS_IMPACT,
                    distribution=PERTDistribution(minimum=0, most_likely=5, maximum=10),
                    aggregation=AggregationType.MAX,
                    weight=1.0,
                    bounds=(0.0, 10.0),
                    name="Business Impact",
                    unit="severity"
                )
            }
        )
    
    def add_component(self, component: CostComponent):
        """Add a cost component"""
        self.components[component.cost_type] = component
    
    def get_component(self, cost_type: CostType) -> Optional[CostComponent]:
        """Get a specific cost component"""
        return self.components.get(cost_type)
    
    def sample(self, n: int = 1) -> Dict[CostType, np.ndarray]:
        """Sample all cost components"""
        return {
            cost_type: component.sample(n)
            for cost_type, component in self.components.items()
        }
    
    def expected_values(self) -> Dict[CostType, float]:
        """Get expected values for all components"""
        return {
            cost_type: component.expected_value()
            for cost_type, component in self.components.items()
        }
    
    def to_vector(self) -> np.ndarray:
        """Convert to numpy array of expected values"""
        return np.array([
            self.components[ct].expected_value()
            for ct in sorted(self.components.keys(), key=lambda x: x.value)
        ])
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "components": {
                ct.name: comp.to_dict()
                for ct, comp in self.components.items()
            },
            "metadata": self.metadata
        }
    
    def __repr__(self) -> str:
        values = self.expected_values()
        return f"EdgeCostVector({', '.join(f'{ct.name}={v:.3f}' for ct, v in values.items())})"


@dataclass
class PathCostVector:
    """
    Aggregated cost vector for a complete path.
    
    Handles proper aggregation of edge costs based on aggregation type.
    """
    edge_costs: List[EdgeCostVector] = field(default_factory=list)
    _cached_aggregated: Optional[Dict[CostType, float]] = field(default=None, repr=False)
    
    def add_edge_cost(self, edge_cost: EdgeCostVector):
        """Add an edge cost to the path"""
        self.edge_costs.append(edge_cost)
        self._cached_aggregated = None
    
    def aggregate(self, n_samples: int = 1000) -> Dict[CostType, Distribution]:
        """
        Aggregate costs along the path using Monte Carlo simulation.
        
        Returns distributions for each cost type.
        """
        if not self.edge_costs:
            return {}
        
        # Get all cost types
        all_types = set()
        for ec in self.edge_costs:
            all_types.update(ec.components.keys())
        
        results = {}
        
        for cost_type in all_types:
            # Collect components for this type
            components = [
                ec.get_component(cost_type)
                for ec in self.edge_costs
                if ec.get_component(cost_type) is not None
            ]
            
            if not components:
                continue
            
            # Sample from each component
            samples = np.array([comp.sample(n_samples) for comp in components])
            
            # Aggregate based on type
            agg_type = components[0].aggregation
            
            if agg_type == AggregationType.SUM:
                aggregated = np.sum(samples, axis=0)
            elif agg_type == AggregationType.PRODUCT:
                aggregated = np.prod(samples, axis=0)
            elif agg_type == AggregationType.MAX:
                aggregated = np.max(samples, axis=0)
            elif agg_type == AggregationType.MIN:
                aggregated = np.min(samples, axis=0)
            else:
                aggregated = np.sum(samples, axis=0)
            
            # Fit a distribution to the aggregated samples
            mean = np.mean(aggregated)
            std = np.std(aggregated)
            
            if std < 1e-10:
                results[cost_type] = ConstantDistribution(value=mean)
            else:
                results[cost_type] = NormalDistribution(mu=mean, sigma=std)
        
        return results
    
    def expected_values(self) -> Dict[CostType, float]:
        """Get expected (mean) aggregated values"""
        aggregated = self.aggregate(n_samples=1000)
        return {ct: dist.mean() for ct, dist in aggregated.items()}
    
    def to_vector(self) -> np.ndarray:
        """Convert to numpy array for Pareto comparison"""
        values = self.expected_values()
        return np.array([
            values.get(ct, 0.0)
            for ct in sorted(CostType, key=lambda x: x.value)
            if ct in values
        ])
    
    def dominates(self, other: 'PathCostVector', minimize: Dict[CostType, bool] = None) -> bool:
        """
        Check if this path dominates another.
        
        By default:
        - TIME_TO_EXPLOIT: minimize (lower is better)
        - SUCCESS_PROBABILITY: maximize (higher is better, so minimize 1-p)
        - BUSINESS_IMPACT: minimize (lower is better for attacker visibility)
        
        Args:
            other: Another path cost vector
            minimize: Dict specifying which objectives to minimize
        
        Returns:
            True if this path dominates the other
        """
        if minimize is None:
            minimize = {
                CostType.TIME_TO_EXPLOIT: True,
                CostType.SUCCESS_PROBABILITY: False,  # Maximize probability
                CostType.BUSINESS_IMPACT: True,
                CostType.DETECTION_PROBABILITY: True  # Minimize detection
            }
        
        this_values = self.expected_values()
        other_values = other.expected_values()
        
        common_types = set(this_values.keys()) & set(other_values.keys())
        
        if not common_types:
            return False
        
        at_least_one_better = False
        
        for ct in common_types:
            this_val = this_values[ct]
            other_val = other_values[ct]
            
            should_minimize = minimize.get(ct, True)
            
            if should_minimize:
                if this_val > other_val:
                    return False
                if this_val < other_val:
                    at_least_one_better = True
            else:
                if this_val < other_val:
                    return False
                if this_val > other_val:
                    at_least_one_better = True
        
        return at_least_one_better


# Utility functions for creating common cost vectors
def create_time_cost(
    mean_hours: float,
    std_hours: float = None
) -> CostComponent:
    """Create a time-to-exploit cost component"""
    if std_hours is None:
        std_hours = mean_hours * 0.3  # Default 30% uncertainty
    
    # Use log-normal for time (always positive, right-skewed)
    # Convert to log-normal parameters
    mu = np.log(mean_hours**2 / np.sqrt(std_hours**2 + mean_hours**2))
    sigma = np.sqrt(np.log(1 + (std_hours/mean_hours)**2))
    
    return CostComponent(
        cost_type=CostType.TIME_TO_EXPLOIT,
        distribution=LogNormalDistribution(mu=mu, sigma=sigma),
        aggregation=AggregationType.SUM,
        name="Time to Exploit",
        unit="hours"
    )


def create_probability_cost(
    success_rate: float,
    confidence: float = 0.8
) -> CostComponent:
    """Create a success probability cost component"""
    # Use beta distribution fitted to have mode at success_rate
    # with specified confidence
    
    # Simple approach: set alpha and beta based on success rate and confidence
    n_observations = int(confidence * 100)  # Pseudo-observations
    alpha = success_rate * n_observations + 1
    beta = (1 - success_rate) * n_observations + 1
    
    return CostComponent(
        cost_type=CostType.SUCCESS_PROBABILITY,
        distribution=BetaDistribution(alpha=alpha, beta=beta),
        aggregation=AggregationType.PRODUCT,
        bounds=(0.0, 1.0),
        name="Success Probability",
        unit="probability"
    )


def create_impact_cost(
    min_impact: float,
    likely_impact: float,
    max_impact: float
) -> CostComponent:
    """Create a business impact cost component using PERT"""
    return CostComponent(
        cost_type=CostType.BUSINESS_IMPACT,
        distribution=PERTDistribution(
            minimum=min_impact,
            most_likely=likely_impact,
            maximum=max_impact
        ),
        aggregation=AggregationType.MAX,
        bounds=(0.0, 10.0),
        name="Business Impact",
        unit="severity (0-10)"
    )


if __name__ == "__main__":
    from rich import print as rprint
    from rich.table import Table
    
    # Test distributions
    rprint("[bold green]Testing Edge Cost Distributions[/bold green]")
    
    # Create a default cost vector
    cost_vector = EdgeCostVector.create_default()
    rprint(f"\nDefault cost vector: {cost_vector}")
    rprint(f"Expected values: {cost_vector.expected_values()}")
    
    # Sample and display statistics
    table = Table(title="Cost Distribution Statistics")
    table.add_column("Cost Type")
    table.add_column("Mean")
    table.add_column("Std")
    table.add_column("5th %ile")
    table.add_column("95th %ile")
    
    for ct, component in cost_vector.components.items():
        dist = component.distribution
        ci = dist.confidence_interval(0.90)
        table.add_row(
            ct.name,
            f"{dist.mean():.3f}",
            f"{dist.std():.3f}",
            f"{ci[0]:.3f}",
            f"{ci[1]:.3f}"
        )
    
    rprint(table)
    
    # Test path aggregation
    rprint("\n[bold green]Testing Path Cost Aggregation[/bold green]")
    
    path = PathCostVector()
    for i in range(3):
        path.add_edge_cost(EdgeCostVector.create_default())
    
    aggregated = path.aggregate()
    rprint(f"Aggregated path costs (3 edges): {path.expected_values()}")
