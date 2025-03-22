#include <stdio.h>
#include <syscall.h>
#include <stdlib.h>

int
main (int argc, char **argv)
{

  int fib;
  int max;
  int arg_arr[4];
  for (int i=0; i<argc-1;i++){
    arg_arr[i] = atoi(argv[i+1]);
  }
//   for (int i=0; i<argc;i++){
//     printf("%d\n",arg_arr[i]);
//   }
  fib = fibonacci(arg_arr[0]);
  max = max_of_four_int(arg_arr[0],arg_arr[1],arg_arr[2],arg_arr[3]);
  printf("%d %d\n",fib, max);
  return EXIT_SUCCESS;
}