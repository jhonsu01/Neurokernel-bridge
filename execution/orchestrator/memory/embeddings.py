"""Lightweight n-gram embedding function for ChromaDB.

Replaces the default onnxruntime-based embeddings which require
AVX CPU instructions not available on all hardware.
"""
from __future__ import annotations
import hashlib


class NGramEmbeddingFunction:
    """Hash-based n-gram embeddings. No onnxruntime/AVX required.

    Produces meaningful cosine similarity for structured event signatures
    like 'cat:FILE:/etc/shadow' by hashing character n-grams into a
    fixed-dimension vector.
    """

    def __init__(self, dim: int = 384, n: int = 3):
        self.dim = dim
        self.n = n

    def __call__(self, input: list[str]) -> list[list[float]]:
        return [self._embed(doc) for doc in input]

    def _embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        lowered = text.lower()
        for i in range(len(lowered) - self.n + 1):
            ngram = lowered[i : i + self.n]
            idx = int(hashlib.md5(ngram.encode()).hexdigest()[:8], 16) % self.dim
            vec[idx] += 1.0
        norm = sum(x * x for x in vec) ** 0.5
        if norm > 0:
            vec = [x / norm for x in vec]
        return vec
