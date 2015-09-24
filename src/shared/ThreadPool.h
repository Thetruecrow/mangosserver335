
#pragma once

#include <ace/Guard_T.h>
#include <ace/Method_Request.h>
#include <ace/OS_NS_unistd.h>
#include <ace/Sched_Params.h>
#include <Platform/Define.h>
#include <Policies/Singleton.h>

#include "DelayExecutor.h"

class ThreadPoolTask;

class ThreadPool : public MaNGOS::Singleton<ThreadPool, MaNGOS::ClassLevelLockable<ThreadPool, ACE_Recursive_Thread_Mutex> >
{
public:
    ThreadPool();
    ~ThreadPool();

    int activate(size_t num_threads, ACE_Method_Request *pre_hook, ACE_Method_Request *post_hook);
    int deactivate();
    bool activated();
    int wait();

    int schedule_task(ThreadPoolTask *request);

    // DO NOT CALL FROM OUTSIDE OF TASK
    void task_finished();

protected:
    DelayExecutor m_executor;
    ACE_Condition_Thread_Mutex m_condition;
    ACE_Thread_Mutex m_mutex;
    size_t pending_tasks;
};

#define sThreadPool ThreadPool::Instance()

class ThreadPoolTask : public ACE_Method_Request
{
public:
    // Must call when overriding
    virtual int call() { sThreadPool.task_finished(); return 0; }
};
