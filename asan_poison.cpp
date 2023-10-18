// g++ -o asan_poison asan_poison.cpp -fsanitize=address

#include <cstddef>
#include <iostream>
#include <memory>

#include "sanitizer/asan_interface.h"

struct allocator {
  allocator(std::size_t max_bytes)
      : buffer_(std::make_unique<std::byte[]>(max_bytes)),
        current_offset_{alignof(std::max_align_t)},
        buffer_size_{max_bytes} {
    ASAN_POISON_MEMORY_REGION(buffer_.get(), max_bytes);
  }

  void* allocate(std::size_t size) {
    std::size_t poisoning_overhead = compute_poisoning_overhead(size);
    std::size_t total_size = size + poisoning_overhead;
    if (current_offset_ + total_size > buffer_size_) {
      //   throw std::bad_alloc();
    }

    void* ptr = buffer_.get() + current_offset_;
    current_offset_ += total_size;

    ASAN_UNPOISON_MEMORY_REGION(ptr, size);

    return ptr;
  }

  void deallocate(void* ptr, std::size_t size) {
    ASAN_POISON_MEMORY_REGION(ptr, size);
  }

 private:
  std::size_t compute_poisoning_overhead(std::size_t user_size) const {
    // I don't think we need these....
    std::size_t required_shadow_bytes = (user_size + 8 - 1) / 8;
    std::size_t round_to = alignof(std::max_align_t);
    std::size_t rounded_shadow_bytes =
        (required_shadow_bytes + round_to - 1) / round_to;

    return rounded_shadow_bytes * round_to;
    // return 0; // bad
  }
  std::unique_ptr<std::byte[]> buffer_;
  std::size_t current_offset_;
  std::size_t buffer_size_;
};

void test_0() {
  const std::size_t max_buffer_bytes = 1024;
  allocator alloc(max_buffer_bytes);

  std::size_t request_size = 8;
  std::byte* data0 = static_cast<std::byte*>(alloc.allocate(request_size));
  std::byte* data1 = static_cast<std::byte*>(alloc.allocate(request_size));

  // notice if there are no padding, we will completely miss this bad access
  //   std::cout << "this is bad: " << static_cast<char>(data0[request_size])
  //             << std::endl;

  std::cout << "this is bad: " << static_cast<char>(data1[request_size])
            << std::endl;
}
void test_1() {
  const std::size_t max_buffer_bytes = 1024;
  allocator alloc(max_buffer_bytes);

  std::size_t request_size = max_buffer_bytes;
  std::byte* data0 = static_cast<std::byte*>(alloc.allocate(request_size));
  std::cout << "this is bad: " << static_cast<char>(data0[request_size])
            << std::endl;
}

int main() {
  test_0();
  test_1();
}