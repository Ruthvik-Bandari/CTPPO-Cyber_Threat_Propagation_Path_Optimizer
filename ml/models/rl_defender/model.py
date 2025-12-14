#!/usr/bin/env python3
"""
RL Defender Model
=================

Deep Q-Network (DQN) for security defense recommendations.
Learns optimal defense strategies given vulnerability states.

Actions:
- Patch specific vulnerabilities
- Apply security configurations
- Enable monitoring
- Do nothing (wait)

State:
- Vulnerability features (CVSS, severity, exploitability)
- Current risk level
- Available resources

Author: Ruthvik
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import numpy as np
import random
import json
import gzip
from collections import deque, namedtuple
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import logging
from tqdm import tqdm

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Experience tuple for replay buffer
Experience = namedtuple('Experience', ['state', 'action', 'reward', 'next_state', 'done'])


class SecurityEnvironment:
    """
    Security environment for RL training.
    
    Simulates a network with vulnerabilities that the agent must defend.
    """
    
    def __init__(
        self,
        scenario: Dict,
        max_steps: int = 20
    ):
        self.initial_state = scenario['state']
        self.actions = scenario['actions']
        self.action_rewards = scenario['action_rewards']
        self.max_steps = max_steps
        
        self.reset()
    
    def reset(self) -> np.ndarray:
        """Reset environment to initial state."""
        self.current_state = self._copy_state(self.initial_state)
        self.step_count = 0
        self.done = False
        self.applied_actions = set()
        
        return self._state_to_vector(self.current_state)
    
    def _copy_state(self, state: Dict) -> Dict:
        """Deep copy of state."""
        return {
            'vulnerabilities': [v.copy() for v in state['vulnerabilities']],
            'total_risk': state['total_risk'],
            'severity_counts': state['severity_counts'].copy()
        }
    
    def _state_to_vector(self, state: Dict) -> np.ndarray:
        """Convert state dict to feature vector."""
        features = []
        
        # Aggregate vulnerability features (max 30 vulns)
        max_vulns = 30
        vuln_features = []
        
        for vuln in state['vulnerabilities'][:max_vulns]:
            vuln_vec = [
                vuln['cvss_score'] / 10.0,  # Normalized CVSS
                1.0 if vuln['severity'] == 'CRITICAL' else 0.0,
                1.0 if vuln['severity'] == 'HIGH' else 0.0,
                1.0 if vuln['severity'] == 'MEDIUM' else 0.0,
                1.0 if vuln['severity'] == 'LOW' else 0.0,
                vuln['exploitability'],
                1.0 if vuln['patch_available'] else 0.0,
                vuln['patch_cost'] / 10.0,
                vuln['business_impact']
            ]
            vuln_features.extend(vuln_vec)
        
        # Pad if fewer vulnerabilities
        vuln_dim = 9  # Features per vulnerability
        while len(vuln_features) < max_vulns * vuln_dim:
            vuln_features.extend([0.0] * vuln_dim)
        
        features.extend(vuln_features[:max_vulns * vuln_dim])
        
        # Global state features
        features.append(state['total_risk'] / 100.0)
        features.append(state['severity_counts'].get('CRITICAL', 0) / 10.0)
        features.append(state['severity_counts'].get('HIGH', 0) / 10.0)
        features.append(state['severity_counts'].get('MEDIUM', 0) / 10.0)
        features.append(state['severity_counts'].get('LOW', 0) / 10.0)
        features.append(len(state['vulnerabilities']) / 30.0)
        
        return np.array(features, dtype=np.float32)
    
    @property
    def state_dim(self) -> int:
        """Dimension of state vector."""
        return 30 * 9 + 6  # 30 vulns * 9 features + 6 global features = 276
    
    @property
    def action_dim(self) -> int:
        """Number of possible actions."""
        return len(self.actions)
    
    def get_action_names(self) -> List[str]:
        """Get list of action names."""
        return list(self.actions.keys())
    
    def step(self, action_idx: int) -> Tuple[np.ndarray, float, bool, Dict]:
        """
        Take an action in the environment.
        
        Args:
            action_idx: Index of action to take
        
        Returns:
            Tuple of (next_state, reward, done, info)
        """
        action_names = self.get_action_names()
        
        if action_idx >= len(action_names):
            # Invalid action
            return self._state_to_vector(self.current_state), -1.0, False, {'error': 'invalid_action'}
        
        action_name = action_names[action_idx]
        action = self.actions[action_name]
        
        # Check if action already applied
        if action_name in self.applied_actions and action['type'] != 'wait':
            reward = -0.5  # Penalty for repeating action
            info = {'error': 'action_already_applied'}
        else:
            # Apply action
            reward = self._apply_action(action_name, action)
            self.applied_actions.add(action_name)
            info = {'action': action_name, 'reward_breakdown': self.action_rewards.get(action_name, 0)}
        
        self.step_count += 1
        
        # Check termination
        if self.step_count >= self.max_steps or self.current_state['total_risk'] < 5:
            self.done = True
        
        next_state = self._state_to_vector(self.current_state)
        
        return next_state, reward, self.done, info
    
    def _apply_action(self, action_name: str, action: Dict) -> float:
        """Apply an action and return reward."""
        action_type = action['type']
        base_reward = self.action_rewards.get(action_name, 0)
        
        if action_type == 'patch':
            # Remove vulnerability
            target_idx = action.get('target_vuln', -1)
            if 0 <= target_idx < len(self.current_state['vulnerabilities']):
                vuln = self.current_state['vulnerabilities'][target_idx]
                
                # Update severity counts
                severity = vuln['severity']
                self.current_state['severity_counts'][severity] -= 1
                
                # Remove vulnerability
                self.current_state['vulnerabilities'].pop(target_idx)
                
                # Update risk
                self._update_risk()
                
                return base_reward
        
        elif action_type == 'configure':
            # Reduce risk from network-based attacks
            target = action.get('target', '')
            risk_reduction = action.get('risk_reduction', 0)
            
            self.current_state['total_risk'] = max(
                0,
                self.current_state['total_risk'] - risk_reduction
            )
            
            return base_reward
        
        elif action_type == 'wait':
            # Small penalty for waiting
            return -0.1
        
        return base_reward
    
    def _update_risk(self):
        """Recalculate total risk after changes."""
        total_risk = 0
        for vuln in self.current_state['vulnerabilities']:
            risk = vuln['cvss_score'] * vuln['exploitability'] * vuln['business_impact']
            total_risk += risk
        
        self.current_state['total_risk'] = min(100.0, total_risk)


class DQNNetwork(nn.Module):
    """Deep Q-Network for action-value estimation."""
    
    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        hidden_dims: List[int] = [512, 256, 128]
    ):
        super().__init__()
        
        layers = []
        prev_dim = state_dim
        
        for hidden_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.2)
            ])
            prev_dim = hidden_dim
        
        layers.append(nn.Linear(prev_dim, action_dim))
        
        self.network = nn.Sequential(*layers)
    
    def forward(self, state: torch.Tensor) -> torch.Tensor:
        """Forward pass to get Q-values for all actions."""
        return self.network(state)


class DuelingDQN(nn.Module):
    """Dueling DQN architecture with separate value and advantage streams."""
    
    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        hidden_dim: int = 256
    ):
        super().__init__()
        
        # Shared feature extractor
        self.feature = nn.Sequential(
            nn.Linear(state_dim, 512),
            nn.ReLU(),
            nn.Linear(512, hidden_dim),
            nn.ReLU()
        )
        
        # Value stream
        self.value_stream = nn.Sequential(
            nn.Linear(hidden_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 1)
        )
        
        # Advantage stream
        self.advantage_stream = nn.Sequential(
            nn.Linear(hidden_dim, 128),
            nn.ReLU(),
            nn.Linear(128, action_dim)
        )
    
    def forward(self, state: torch.Tensor) -> torch.Tensor:
        """Forward pass with value-advantage decomposition."""
        features = self.feature(state)
        
        value = self.value_stream(features)
        advantage = self.advantage_stream(features)
        
        # Combine value and advantage
        q_values = value + (advantage - advantage.mean(dim=-1, keepdim=True))
        
        return q_values


class ReplayBuffer:
    """Experience replay buffer for DQN training."""
    
    def __init__(self, capacity: int = 100000):
        self.buffer = deque(maxlen=capacity)
    
    def push(self, experience: Experience):
        """Add experience to buffer."""
        self.buffer.append(experience)
    
    def sample(self, batch_size: int) -> List[Experience]:
        """Sample a batch of experiences."""
        return random.sample(self.buffer, min(batch_size, len(self.buffer)))
    
    def __len__(self):
        return len(self.buffer)


class PrioritizedReplayBuffer:
    """Prioritized experience replay buffer."""
    
    def __init__(
        self,
        capacity: int = 100000,
        alpha: float = 0.6,
        beta: float = 0.4
    ):
        self.capacity = capacity
        self.alpha = alpha
        self.beta = beta
        self.buffer = []
        self.priorities = np.zeros(capacity, dtype=np.float32)
        self.position = 0
        self.max_priority = 1.0
    
    def push(self, experience: Experience):
        """Add experience with max priority."""
        if len(self.buffer) < self.capacity:
            self.buffer.append(experience)
        else:
            self.buffer[self.position] = experience
        
        self.priorities[self.position] = self.max_priority
        self.position = (self.position + 1) % self.capacity
    
    def sample(self, batch_size: int) -> Tuple[List[Experience], np.ndarray, np.ndarray]:
        """Sample batch with importance sampling weights."""
        n = len(self.buffer)
        
        # Calculate probabilities
        priorities = self.priorities[:n] ** self.alpha
        probs = priorities / priorities.sum()
        
        # Sample indices
        indices = np.random.choice(n, min(batch_size, n), p=probs, replace=False)
        
        # Calculate importance sampling weights
        weights = (n * probs[indices]) ** (-self.beta)
        weights /= weights.max()
        
        experiences = [self.buffer[i] for i in indices]
        
        return experiences, indices, weights
    
    def update_priorities(self, indices: np.ndarray, priorities: np.ndarray):
        """Update priorities after learning."""
        for idx, priority in zip(indices, priorities):
            self.priorities[idx] = priority + 1e-6
            self.max_priority = max(self.max_priority, priority)
    
    def __len__(self):
        return len(self.buffer)


class RLDefender:
    """
    RL agent for security defense recommendations.
    
    Uses Double DQN with prioritized experience replay.
    """
    
    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        device: str = "mps" if torch.backends.mps.is_available() else "cpu",
        learning_rate: float = 1e-4,
        gamma: float = 0.99,
        epsilon_start: float = 1.0,
        epsilon_end: float = 0.01,
        epsilon_decay: float = 0.995,
        target_update_freq: int = 100,
        use_dueling: bool = True,
        use_prioritized: bool = True
    ):
        self.device = device
        self.gamma = gamma
        self.epsilon = epsilon_start
        self.epsilon_end = epsilon_end
        self.epsilon_decay = epsilon_decay
        self.target_update_freq = target_update_freq
        self.action_dim = action_dim
        
        # Networks
        if use_dueling:
            self.policy_net = DuelingDQN(state_dim, action_dim).to(device)
            self.target_net = DuelingDQN(state_dim, action_dim).to(device)
        else:
            self.policy_net = DQNNetwork(state_dim, action_dim).to(device)
            self.target_net = DQNNetwork(state_dim, action_dim).to(device)
        
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()
        
        # Optimizer
        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=learning_rate)
        
        # Replay buffer
        if use_prioritized:
            self.replay_buffer = PrioritizedReplayBuffer()
        else:
            self.replay_buffer = ReplayBuffer()
        
        self.use_prioritized = use_prioritized
        
        # Training stats
        self.training_step = 0
        self.history = {
            'episode_rewards': [],
            'episode_lengths': [],
            'losses': [],
            'epsilons': []
        }
    
    def select_action(self, state: np.ndarray, training: bool = True) -> int:
        """Select action using epsilon-greedy policy."""
        if training and random.random() < self.epsilon:
            return random.randrange(self.action_dim)
        
        with torch.no_grad():
            state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
            q_values = self.policy_net(state_tensor)
            return q_values.argmax().item()
    
    def train_step(self, batch_size: int = 64) -> float:
        """Perform one training step."""
        if len(self.replay_buffer) < batch_size:
            return 0.0
        
        if self.use_prioritized:
            experiences, indices, weights = self.replay_buffer.sample(batch_size)
            weights = torch.FloatTensor(weights).to(self.device)
        else:
            experiences = self.replay_buffer.sample(batch_size)
            weights = torch.ones(len(experiences)).to(self.device)
        
        # Prepare batch
        states = torch.FloatTensor([e.state for e in experiences]).to(self.device)
        actions = torch.LongTensor([e.action for e in experiences]).to(self.device)
        rewards = torch.FloatTensor([e.reward for e in experiences]).to(self.device)
        next_states = torch.FloatTensor([e.next_state for e in experiences]).to(self.device)
        dones = torch.FloatTensor([e.done for e in experiences]).to(self.device)
        
        # Current Q values
        current_q = self.policy_net(states).gather(1, actions.unsqueeze(1)).squeeze(1)
        
        # Double DQN: use policy net to select actions, target net to evaluate
        with torch.no_grad():
            next_actions = self.policy_net(next_states).argmax(1)
            next_q = self.target_net(next_states).gather(1, next_actions.unsqueeze(1)).squeeze(1)
            target_q = rewards + (1 - dones) * self.gamma * next_q
        
        # Calculate loss
        td_errors = (current_q - target_q).abs()
        loss = (weights * F.smooth_l1_loss(current_q, target_q, reduction='none')).mean()
        
        # Update priorities
        if self.use_prioritized:
            self.replay_buffer.update_priorities(indices, td_errors.detach().cpu().numpy())
        
        # Optimize
        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.policy_net.parameters(), 1.0)
        self.optimizer.step()
        
        # Update target network
        self.training_step += 1
        if self.training_step % self.target_update_freq == 0:
            self.target_net.load_state_dict(self.policy_net.state_dict())
        
        return loss.item()
    
    def decay_epsilon(self):
        """Decay exploration rate."""
        self.epsilon = max(self.epsilon_end, self.epsilon * self.epsilon_decay)
    
    def train(
        self,
        scenarios: List[Dict],
        episodes: int = 1000,
        batch_size: int = 64,
        save_dir: Optional[Path] = None,
        eval_freq: int = 100
    ) -> Dict:
        """
        Train the agent on security scenarios.
        
        Args:
            scenarios: List of security scenarios
            episodes: Number of training episodes
            batch_size: Batch size for training
            save_dir: Directory to save checkpoints
            eval_freq: Frequency of evaluation logging
        
        Returns:
            Training history
        """
        logger.info(f"Training on {self.device}")
        logger.info(f"Scenarios: {len(scenarios)}")
        
        best_avg_reward = float('-inf')
        
        for episode in range(episodes):
            # Sample random scenario
            scenario = random.choice(scenarios)
            env = SecurityEnvironment(scenario)
            
            state = env.reset()
            episode_reward = 0
            episode_length = 0
            
            while not env.done:
                # Select action
                action = self.select_action(state)
                
                # Take step
                next_state, reward, done, info = env.step(action)
                
                # Store experience
                experience = Experience(state, action, reward, next_state, done)
                self.replay_buffer.push(experience)
                
                # Train
                loss = self.train_step(batch_size)
                
                state = next_state
                episode_reward += reward
                episode_length += 1
            
            # Decay epsilon
            self.decay_epsilon()
            
            # Record history
            self.history['episode_rewards'].append(episode_reward)
            self.history['episode_lengths'].append(episode_length)
            self.history['epsilons'].append(self.epsilon)
            
            # Logging
            if (episode + 1) % eval_freq == 0:
                avg_reward = np.mean(self.history['episode_rewards'][-eval_freq:])
                avg_length = np.mean(self.history['episode_lengths'][-eval_freq:])
                
                logger.info(
                    f"Episode {episode + 1}/{episodes} - "
                    f"Avg Reward: {avg_reward:.2f}, "
                    f"Avg Length: {avg_length:.1f}, "
                    f"Epsilon: {self.epsilon:.3f}"
                )
                
                # Save best model
                if avg_reward > best_avg_reward:
                    best_avg_reward = avg_reward
                    if save_dir:
                        self.save_checkpoint(save_dir / "best_rl_model.pt")
        
        return self.history
    
    def evaluate(
        self,
        scenarios: List[Dict],
        num_episodes: int = 100
    ) -> Dict:
        """Evaluate the agent."""
        rewards = []
        lengths = []
        actions_taken = []
        
        for i in range(min(num_episodes, len(scenarios))):
            scenario = scenarios[i]
            env = SecurityEnvironment(scenario)
            
            state = env.reset()
            episode_reward = 0
            episode_actions = []
            
            while not env.done:
                action = self.select_action(state, training=False)
                next_state, reward, done, info = env.step(action)
                
                episode_reward += reward
                episode_actions.append(env.get_action_names()[action] if action < len(env.get_action_names()) else 'invalid')
                
                state = next_state
            
            rewards.append(episode_reward)
            lengths.append(len(episode_actions))
            actions_taken.append(episode_actions)
        
        # Calculate metrics
        results = {
            'mean_reward': np.mean(rewards),
            'std_reward': np.std(rewards),
            'mean_length': np.mean(lengths),
            'max_reward': np.max(rewards),
            'min_reward': np.min(rewards),
            'action_distribution': self._calculate_action_distribution(actions_taken)
        }
        
        return results
    
    def _calculate_action_distribution(self, actions_taken: List[List[str]]) -> Dict[str, float]:
        """Calculate distribution of actions taken."""
        all_actions = [a for episode in actions_taken for a in episode]
        total = len(all_actions)
        
        if total == 0:
            return {}
        
        distribution = {}
        for action in set(all_actions):
            distribution[action] = all_actions.count(action) / total
        
        return distribution
    
    def recommend_actions(
        self,
        state_dict: Dict,
        top_k: int = 5
    ) -> List[Tuple[str, float]]:
        """
        Get top-k recommended actions for a given state.
        
        Args:
            state_dict: State dictionary
            top_k: Number of recommendations to return
        
        Returns:
            List of (action_name, q_value) tuples
        """
        # Create dummy environment to get state vector
        dummy_scenario = {
            'state': state_dict,
            'actions': {f'action_{i}': {'type': 'wait'} for i in range(50)},
            'action_rewards': {}
        }
        env = SecurityEnvironment(dummy_scenario)
        state_vector = env._state_to_vector(state_dict)
        
        with torch.no_grad():
            state_tensor = torch.FloatTensor(state_vector).unsqueeze(0).to(self.device)
            q_values = self.policy_net(state_tensor).squeeze().cpu().numpy()
        
        # Get top-k actions
        top_indices = np.argsort(q_values)[-top_k:][::-1]
        
        recommendations = []
        action_names = env.get_action_names()
        for idx in top_indices:
            if idx < len(action_names):
                recommendations.append((action_names[idx], float(q_values[idx])))
        
        return recommendations
    
    def save_checkpoint(self, path: Path):
        """Save model checkpoint."""
        path.parent.mkdir(parents=True, exist_ok=True)
        
        checkpoint = {
            'policy_net_state_dict': self.policy_net.state_dict(),
            'target_net_state_dict': self.target_net.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'epsilon': self.epsilon,
            'training_step': self.training_step,
            'history': self.history
        }
        
        torch.save(checkpoint, path)
    
    def load_checkpoint(self, path: Path):
        """Load model checkpoint."""
        checkpoint = torch.load(path, map_location=self.device)
        self.policy_net.load_state_dict(checkpoint['policy_net_state_dict'])
        self.target_net.load_state_dict(checkpoint['target_net_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.epsilon = checkpoint.get('epsilon', self.epsilon_end)
        self.training_step = checkpoint.get('training_step', 0)
        self.history = checkpoint.get('history', self.history)


def load_scenarios(file_path: Path) -> List[Dict]:
    """Load RL scenarios from file."""
    with gzip.open(file_path, 'rt', encoding='utf-8') as f:
        return json.load(f)


def main():
    """Training pipeline for RL defender."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Train RL defender")
    parser.add_argument("--data-dir", type=str, required=True, help="Data directory")
    parser.add_argument("--output-dir", type=str, required=True, help="Output directory")
    parser.add_argument("--episodes", type=int, default=5000, help="Training episodes")
    parser.add_argument("--batch-size", type=int, default=64, help="Batch size")
    parser.add_argument("--lr", type=float, default=1e-4, help="Learning rate")
    parser.add_argument("--gamma", type=float, default=0.99, help="Discount factor")
    parser.add_argument("--no-dueling", action="store_true", help="Disable dueling architecture")
    parser.add_argument("--no-prioritized", action="store_true", help="Disable prioritized replay")
    
    args = parser.parse_args()
    
    data_dir = Path(args.data_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load data
    logger.info("Loading scenarios...")
    train_scenarios = load_scenarios(data_dir / "rl_train.json.gz")
    val_scenarios = load_scenarios(data_dir / "rl_val.json.gz")
    test_scenarios = load_scenarios(data_dir / "rl_test.json.gz")
    
    # Get dimensions from first scenario
    env = SecurityEnvironment(train_scenarios[0])
    state_dim = env.state_dim
    action_dim = env.action_dim
    
    logger.info(f"State dim: {state_dim}, Action dim: {action_dim}")
    
    # Initialize agent
    agent = RLDefender(
        state_dim=state_dim,
        action_dim=action_dim,
        learning_rate=args.lr,
        gamma=args.gamma,
        use_dueling=not args.no_dueling,
        use_prioritized=not args.no_prioritized
    )
    
    # Train
    history = agent.train(
        train_scenarios,
        episodes=args.episodes,
        batch_size=args.batch_size,
        save_dir=output_dir
    )
    
    # Evaluate
    logger.info("\nEvaluating on test scenarios...")
    results = agent.evaluate(test_scenarios)
    
    logger.info(f"\nTest Results:")
    logger.info(f"Mean Reward: {results['mean_reward']:.2f} (+/- {results['std_reward']:.2f})")
    logger.info(f"Mean Episode Length: {results['mean_length']:.1f}")
    logger.info(f"Action Distribution: {results['action_distribution']}")
    
    # Save results
    results_file = output_dir / "rl_test_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"\nResults saved to {results_file}")


if __name__ == "__main__":
    main()
