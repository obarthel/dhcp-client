/*
 * AmigaOS style doubly-linked lists
 *
 * Manually "upcoded" from the 68000 assembly language
 * macros, etc.
 *
 * Public domain
 *
 * :ts=4
 */

#ifndef _LIST_NODE_H
#define _LIST_NODE_H

/****************************************************************************/

#include <stdbool.h>

/****************************************************************************/

struct Node
{
	struct Node *	ln_Succ;
	struct Node *	ln_Pred;
};

struct List
{
	struct Node *	lh_Head;
	struct Node *	lh_Tail;
	struct Node *	lh_TailPred;
};

/****************************************************************************/

void new_list(struct List *list);
void add_node_to_list_head(struct List *list, struct Node *node);
void add_node_to_list_tail(struct List *list, struct Node *node);
void insert_node(struct List *list __attribute__((unused)), struct Node *list_node, struct Node *node);
void remove_node(struct Node *node);
struct Node *remove_list_head(struct List *list);
struct Node *remove_list_tail(struct List *list);
bool is_list_empty(const struct List *list);
const struct Node *get_list_head(const struct List *list);
const struct Node *get_list_tail(const struct List *list);
const struct Node *get_next_node(const struct Node *node);
const struct Node *get_previous_node(const struct Node *node);

/****************************************************************************/

#endif /* _LIST_NODE_H */
