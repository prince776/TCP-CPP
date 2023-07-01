#pragma once

#include <condition_variable>
#include <future>
#include <mutex>
#include <queue>
#include <thread>
#include <utility>
#include <vector>

class ThreadPool {
  public:
    ThreadPool() = default;

    ThreadPool(int poolSize) {
        threads = std::vector<std::thread>(poolSize);
        for (auto& thread : threads) {
            thread = std::thread(&ThreadPool::work, this);
        }
    }

    template <typename Func>
    [[nodiscard]] std::future<void> pushTask(Func func) {
        std::packaged_task<void()> task(func);
        std::future<void> res = task.get_future();

        std::scoped_lock lock(queueMutex);
        tasks.push(std::move(task));
        queueCondn.notify_one();
        return res;
    }

    template <typename Func>
    void pushDetchedTask(Func func) {
        std::packaged_task<void()> task(func);

        std::scoped_lock lock(queueMutex);
        tasks.push(std::move(task));
        queueCondn.notify_one();
    }

  private:
    void work() {
        while (true) {
            std::packaged_task<void()> task;
            {
                std::unique_lock lock(queueMutex);

                queueCondn.wait(lock, [&] {
                    return !tasks.empty();
                });

                task = std::move(tasks.front());
                tasks.pop();
            }
            task();
            // if (task.get_future().valid()) {
            //     task.get_future().get();
            // }
        }
    }

  private:
    std::queue<std::packaged_task<void()>> tasks;
    std::vector<std::thread> threads;
    std::mutex queueMutex;
    std::condition_variable queueCondn;
};
