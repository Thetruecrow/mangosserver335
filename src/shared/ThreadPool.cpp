
#include "Common.h"
#include "Errors.h"
#include "ThreadPool.h"

#define CLASS_LOCK MaNGOS::ClassLevelLockable<ThreadPool, ACE_Recursive_Thread_Mutex>
INSTANTIATE_SINGLETON_2(ThreadPool, CLASS_LOCK);
INSTANTIATE_CLASS_MUTEX(ThreadPool, ACE_Recursive_Thread_Mutex);

ThreadPool::ThreadPool() : m_mutex(), m_condition(m_mutex), m_executor(), pending_tasks(0)
{
}

ThreadPool::~ThreadPool()
{
    deactivate();
}

int ThreadPool::activate(size_t num_threads, ACE_Method_Request *pre_hook, ACE_Method_Request *post_hook)
{
    return m_executor.activate((int)num_threads, pre_hook, post_hook);
}

int ThreadPool::deactivate()
{
    wait();

    return m_executor.deactivate();
}

int ThreadPool::wait()
{
    ACE_GUARD_RETURN(ACE_Thread_Mutex, guard, m_mutex, -1);

    while (pending_tasks > 0)
        m_condition.wait();

    return 0;
}

int ThreadPool::schedule_task(ThreadPoolTask *request)
{
    ACE_GUARD_RETURN(ACE_Thread_Mutex, guard, m_mutex, -1);

    ++pending_tasks;
    if (m_executor.execute(request) == -1)
    {
        ACE_DEBUG((LM_ERROR, ACE_TEXT("(%t) \n"), ACE_TEXT("Failed to schedule Task")));
        --pending_tasks;
        delete request;
        return -1;
    }

    return 0;
}

bool ThreadPool::activated()
{
    return m_executor.activated();
}

void ThreadPool::task_finished()
{
    ACE_GUARD(ACE_Thread_Mutex, guard, m_mutex);
    if (pending_tasks == 0)
    {
        ACE_ERROR((LM_ERROR, ACE_TEXT("(%t)\n"), ACE_TEXT("ThreadPool::task_finished BUG, report to devs")));
        return;
    }

    --pending_tasks;
    m_condition.broadcast();
}