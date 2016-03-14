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

#include <stddef.h>
#include <assert.h>

/****************************************************************************/

#include "list_node.h"

/****************************************************************************/

void
new_list(struct List * list)
{
	assert(list != NULL);

	list->lh_Tail		= NULL;
	list->lh_Head		= (struct Node *)&list->lh_Tail;
	list->lh_TailPred	= (struct Node *)list;
}

/****************************************************************************/

void
add_node_to_list_head(
	struct List * list,
	struct Node * node)
{
	struct Node * head;

	assert(list != NULL && node != NULL);
	assert(list->lh_Head != NULL);

	head			= list->lh_Head;
	list->lh_Head	= node;
	node->ln_Succ	= head;
	node->ln_Pred	= (struct Node *)list;
	head->ln_Pred	= node;
}

/****************************************************************************/

void
add_node_to_list_tail(
	struct List * list,
	struct Node * node)
{
	struct Node * tail;
	struct Node * tailPred;

	assert(list != NULL && node != NULL);
	assert(list->lh_TailPred != NULL);

	tail				= (struct Node *)&list->lh_Tail;
	tailPred			= tail->ln_Pred;
	tail->ln_Pred		= node;
	node->ln_Succ		= tail;
	node->ln_Pred		= tailPred;
	tailPred->ln_Succ	= node;
}

/****************************************************************************/

void
insert_node(
	struct List * list __attribute__((unused)), /* Note: list parameter is only used for assert() checks. */
	struct Node * list_node,
	struct Node * node)
{
	assert(list != NULL && list_node != NULL && node != NULL);
	assert(list->lh_Head != NULL && list->lh_TailPred != NULL);

	if(list_node->ln_Succ == NULL)
	{
		struct Node * pred;

		node->ln_Succ		= list_node;
		pred				= list_node->ln_Pred;
		node->ln_Pred		= pred;
		list_node->ln_Pred	= node;
		pred->ln_Succ		= node;
	}
	else
	{
		struct Node * succ;

		succ				= list_node->ln_Succ;
		node->ln_Succ		= succ;
		node->ln_Pred		= list_node;
		succ->ln_Pred		= node;
		list_node->ln_Succ	= node;
	}
}

/****************************************************************************/

void
remove_node(struct Node * node)
{
	if(node != NULL)
	{
		struct Node * next;
		struct Node * pred;

		assert(node->ln_Succ != NULL && node->ln_Pred != NULL);

		next			= node->ln_Succ;
		pred			= node->ln_Pred;
		pred->ln_Succ	= next;
		next->ln_Pred	= pred;

		node->ln_Pred = node->ln_Succ = NULL;
	}
}

/****************************************************************************/

struct Node *
remove_list_head(struct List * list)
{
	struct Node * result;

	assert(list == NULL || list->lh_Head != NULL);

	if(!is_list_empty(list))
	{
		result = list->lh_Head;

		remove_node(result);
	}
	else
	{
		result = NULL;
	}

	return(result);
}

/****************************************************************************/

struct Node *
remove_list_tail(struct List * list)
{
	struct Node * result;

	assert(list == NULL || list->lh_TailPred != NULL);

	if(!is_list_empty(list))
	{
		result = list->lh_TailPred;

		remove_node(result);
	}
	else
	{
		result = NULL;
	}
	
	return(result);
}

/****************************************************************************/

bool
is_list_empty(const struct List * list)
{
	bool result;

	assert(list == NULL || list->lh_Head != NULL);

	result = (list == NULL || list->lh_Head->ln_Succ == NULL);

	return(result);
}

/****************************************************************************/

const struct Node *
get_list_head(const struct List * list)
{
	const struct Node * result;

	assert(list == NULL || list->lh_Head != NULL);

	if(!is_list_empty(list))
		result = list->lh_Head;
	else
		result = NULL;

	return(result);
}

/****************************************************************************/

const struct Node *
get_list_tail(const struct List * list)
{
	const struct Node * result;

	assert(list == NULL || list->lh_TailPred != NULL);

	if(!is_list_empty(list))
		result = list->lh_TailPred;
	else
		result = NULL;

	return(result);
}

/****************************************************************************/

const struct Node *
get_next_node(const struct Node * node)
{
	const struct Node * result;

	assert(node == NULL || node->ln_Succ != NULL);

	if(node != NULL && node->ln_Succ->ln_Succ != NULL)
		result = node->ln_Succ;
	else
		result = NULL;

	return(result);
}

/****************************************************************************/

const struct Node *
get_previous_node(const struct Node * node)
{
	const struct Node * result;

	assert(node == NULL || node->ln_Pred != NULL);

	if(node != NULL && node->ln_Pred->ln_Pred != NULL)
		result = node->ln_Pred;
	else
		result = NULL;

	return(result);
}
