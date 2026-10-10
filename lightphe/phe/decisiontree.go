package phe

import (
	"fmt"
	"math/big"
)

// DecisionTree is either a leaf carrying an integer output, or a decision node
// that continues with IfZero when the input bit at Variable is 0 and with
// IfOne when it is 1. Build trees with Leaf and Node. Sub trees may be shared
// between several parents, which turns the tree into a DAG; shared sub trees
// are evaluated once.
type DecisionTree struct {
	// Value is the output of a leaf. It is nil for decision nodes.
	Value *big.Int

	// Variable is the index of the input bit a decision node checks.
	Variable int

	// IfZero and IfOne are the sub trees of a decision node.
	IfZero, IfOne *DecisionTree
}

// Leaf builds a leaf that outputs value.
func Leaf(value int64) *DecisionTree {
	return &DecisionTree{Value: big.NewInt(value)}
}

// Node builds a decision node that checks the input bit at variable.
func Node(variable int, ifZero, ifOne *DecisionTree) *DecisionTree {
	return &DecisionTree{Variable: variable, IfZero: ifZero, IfOne: ifOne}
}

// IsLeaf reports whether the tree is a leaf.
func (t *DecisionTree) IsLeaf() bool { return t.Value != nil }

// Depth returns the maximum number of decisions on a path of the tree.
func (t *DecisionTree) Depth() int {
	if t.IsLeaf() {
		return 0
	}
	d0, d1 := t.IfZero.Depth(), t.IfOne.Depth()
	if d1 > d0 {
		d0 = d1
	}
	return 1 + d0
}

// Evaluate runs the tree on plain input bits.
func (t *DecisionTree) Evaluate(bits []int) *big.Int {
	node := t
	for !node.IsLeaf() {
		if bits[node.Variable] == 1 {
			node = node.IfOne
		} else {
			node = node.IfZero
		}
	}
	return new(big.Int).Set(node.Value)
}

// String implements fmt.Stringer.
func (t *DecisionTree) String() string {
	if t.IsLeaf() {
		return t.Value.String()
	}
	return fmt.Sprintf("(%d, %s, %s)", t.Variable, t.IfZero, t.IfOne)
}
