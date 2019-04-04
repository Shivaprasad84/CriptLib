#pragma once

class stack
{
    struct node
    {
        int id;
        node* next;
    }* top;
    
    public:
        stack();

        void push(int _id);

        int pop();
};