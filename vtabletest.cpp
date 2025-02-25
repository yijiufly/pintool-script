#include <iostream>
#include <string>
#include <stdio.h>

using namespace std;
class A
{
public:
  void foo();
};

void A::foo()
{
  cout << "Hello this is foo" << endl;
}

class B
{
public:
  virtual void bar();
  virtual void qux();
};

void B::bar()
{
  cout << "This is B's implementation of bar" << endl;
}

void B::qux()
{
  cout << "This is B's implementation of qux" << endl;
}

class C : public B
{
public:
  void bar() override;
};

void C::bar()
{
  cout << "This is C's implementation of bar" << endl;
}

int main() {
    // Create an object of C class
    B* b = new C();
    b->bar();

    b = new B();
    b->bar();
    
    return 0;
}