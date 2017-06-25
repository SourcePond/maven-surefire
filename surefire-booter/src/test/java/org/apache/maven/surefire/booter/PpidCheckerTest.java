package org.apache.maven.surefire.booter;

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import org.junit.Test;

import java.util.concurrent.TimeUnit;

import static org.apache.commons.lang3.SystemUtils.IS_OS_UNIX;
import static org.apache.commons.lang3.SystemUtils.IS_OS_WINDOWS;
import static org.fest.assertions.Assertions.assertThat;
import static org.junit.Assume.assumeTrue;

/**
 * Testing {@link PpidChecker} on a platform.
 *
 * @author <a href="mailto:tibordigana@apache.org">Tibor Digana (tibor17)</a>
 * @since 2.20.1
 */
public class PpidCheckerTest
{
    @Test
    public void shouldHavePid()
    {
        String pid = PpidChecker.pid();

        assertThat( pid )
                .isNotNull();

        assertThat( pid )
                .matches( "^[\\d]+$" );
    }

    @Test
    public void shouldHavePpidAsWindows()
    {
        assumeTrue( IS_OS_WINDOWS );

        ProcessInfo processInfo = PpidChecker.windows( PpidChecker.pid() );

        assertThat( processInfo )
                .isNotNull();

        assertThat( processInfo.getPID() )
                .isNotNull();

        assertThat( processInfo.getPID() )
                .matches( "^[\\d]+$" );

        assertThat( processInfo.getTime() )
                .isNotNull();

        processInfo = PpidChecker.windows( processInfo.getPID() );

        assertThat( processInfo.getPID() )
                .isNotNull();

        assertThat( processInfo.getPID() )
                .matches( "^[\\d]+$" );

        assertThat( processInfo.getTime() )
                .isNotNull();
    }

    @Test
    public void shouldHavePpidAsUnix()
    {
        assumeTrue( IS_OS_UNIX );

        ProcessInfo processInfo = PpidChecker.unix();

        assertThat( processInfo )
                .isNotNull();

        assertThat( processInfo.getPID() )
                .isNotNull();

        assertThat( processInfo.getPID() )
                .isEqualTo( "pid not needed in unix" );

        assertThat( processInfo.getTime() )
                .isNotNull();
    }

    @Test
    public void shouldFindAliveParentProcess()
            throws InterruptedException
    {
        PpidChecker checker = new PpidChecker();

        assertThat( checker.canUse() )
                .isTrue();

        TimeUnit.MILLISECONDS.sleep( 100L );

        assertThat( checker.isParentProcessAlive() )
                .isTrue();
    }
}
