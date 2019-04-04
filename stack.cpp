#include "stack.hpp"

stack::stack()
{
    top = nullptr;
}

void stack::push(int _id)
{
    node *temp = new node;
    temp->id = _id;
    temp->next = top;
    top = temp;
}

int stack::pop()
{
    node *x = top;
    top = top->next;
    int temp = x->id;
    delete x;
    return temp;
}